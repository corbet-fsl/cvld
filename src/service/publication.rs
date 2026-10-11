//! Live authorization limits are separate from a proof's original context time.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(test)]
mod tests;

tokio::task_local! {
    static ACTIVE: Arc<Publication>;
}

pub(crate) struct Publication {
    clock: Arc<dyn Clock>,
    observed: AtomicU64,
    deadline: AtomicU64,
    invalid: AtomicBool,
    effect: Effect,
    last: std::sync::Mutex<String>,
}

impl Publication {
    pub(super) fn new(clock: Arc<dyn Clock>, ctx: &Context, effect: Effect) -> Self {
        Self {
            clock,
            observed: AtomicU64::new(ctx.now),
            deadline: AtomicU64::new(ctx.grant.as_ref().map_or(u64::MAX, |g| g.expires)),
            invalid: AtomicBool::new(false),
            effect,
            last: std::sync::Mutex::new(String::new()),
        }
    }

    fn check(&self) -> Result<()> {
        let now = self.clock.now();
        let previous = self.observed.fetch_max(now, Ordering::SeqCst);
        if now < previous || now >= self.deadline.load(Ordering::SeqCst) {
            self.invalid.store(true, Ordering::SeqCst);
        }
        if self.invalid.load(Ordering::SeqCst) {
            Err(Error::Unauthorized)
        } else {
            Ok(())
        }
    }

    pub(crate) async fn run<T>(
        self,
        operation: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        self.check()?;
        let publication = Arc::new(self);
        ACTIVE
            .scope(publication.clone(), async move {
                let result = operation.await;
                if publication.check().is_err() {
                    eprintln!(
                        "DIAG publication failed now={} observed={} deadline={} last={}",
                        publication.clock.now(),
                        publication.observed.load(Ordering::SeqCst),
                        publication.deadline.load(Ordering::SeqCst),
                        publication.last.lock().unwrap()
                    );
                    // The action may already have committed. Withhold its output;
                    // neither rollback nor safe automatic retry is implied.
                    return Err(match publication.effect {
                        Effect::Check => Error::Unauthorized,
                        Effect::Record => Error::Reconcile,
                    });
                }
                result
            })
            .await
    }
}

/// Bind an exclusive deadline obtained from owned, authenticated pending state.
/// Direct library calls still perform their own validation without this scope.
#[track_caller]
pub(crate) fn expires_at(deadline: u64) -> Result<()> {
    let location = std::panic::Location::caller();
    ACTIVE
        .try_with(|publication| {
            let before = publication.deadline.fetch_min(deadline, Ordering::SeqCst);
            if deadline < before {
                *publication.last.lock().unwrap() = format!(
                    "{}:{} deadline={deadline}",
                    location.file(),
                    location.line()
                );
            }
            publication.check()
        })
        .unwrap_or(Ok(()))
}
