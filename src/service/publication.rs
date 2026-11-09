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
}

impl Publication {
    pub(super) fn new(clock: Arc<dyn Clock>, ctx: &Context, effect: Effect) -> Self {
        Self {
            clock,
            observed: AtomicU64::new(ctx.now),
            deadline: AtomicU64::new(ctx.grant.as_ref().map_or(u64::MAX, |g| g.expires)),
            invalid: AtomicBool::new(false),
            effect,
        }
    }

    fn check(&self) -> Result<()> {
        let now = self.clock.now();
        let previous = self.observed.fetch_max(now, Ordering::SeqCst);
        if now < previous {
            crate::refusal::note(crate::refusal::Reason::ClockBehind);
            self.invalid.store(true, Ordering::SeqCst);
        } else if now >= self.deadline.load(Ordering::SeqCst) {
            crate::refusal::note(crate::refusal::Reason::SessionExpired);
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
pub(crate) fn expires_at(deadline: u64) -> Result<()> {
    ACTIVE
        .try_with(|publication| {
            publication.deadline.fetch_min(deadline, Ordering::SeqCst);
            publication.check()
        })
        .unwrap_or(Ok(()))
}
