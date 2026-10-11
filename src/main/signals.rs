//! One signal owner spans startup, serving and the original shutdown budget.
use super::*;
use std::future::Future;
use tokio::sync::watch;

pub(super) struct Signals {
    received: watch::Receiver<Option<Instant>>,
    owner: tokio::task::JoinHandle<()>,
}
impl Signals {
    pub(super) async fn install(
        budget: Duration,
        deadline: Arc<OnceLock<Instant>>,
    ) -> Result<Self> {
        // On Unix both handlers are installed synchronously, before a factory
        // is ever polled. The same streams remain owned through server drain.
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(Error::Unavailable.redact())?;
        #[cfg(unix)]
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(Error::Unavailable.redact())?;
        #[cfg(not(unix))]
        let mut interrupt = Box::pin(tokio::signal::ctrl_c());
        #[cfg(not(unix))]
        let interrupted = std::future::poll_fn(|cx| {
            use std::task::Poll;
            Poll::Ready(matches!(interrupt.as_mut().poll(cx), Poll::Ready(_)))
        })
        .await;
        let (sent, received) = watch::channel(None);
        let owner = tokio::spawn(async move {
            #[cfg(unix)]
            tokio::select! {
                _ = terminate.recv() => {},
                _ = interrupt.recv() => {},
            }
            #[cfg(not(unix))]
            if !interrupted {
                let _ = interrupt.await;
            }
            let began = Instant::now();
            let until = began.checked_add(budget).unwrap_or(began);
            let _ = deadline.set(until);
            sent.send_replace(Some(*deadline.get().unwrap_or(&until)));
        });
        Ok(Self { received, owner })
    }
    pub(super) fn receiver(&self) -> watch::Receiver<Option<Instant>> {
        self.received.clone()
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        self.owner.abort();
    }
}

pub(super) async fn wait(receiver: &mut watch::Receiver<Option<Instant>>) -> Result<Instant> {
    loop {
        if let Some(until) = *receiver.borrow_and_update() {
            return Ok(until);
        }
        receiver
            .changed()
            .await
            .map_err(Error::Unavailable.redact())?;
    }
}

pub(super) async fn open<T>(
    opening: impl Future<Output = Result<T>>,
    receiver: &mut watch::Receiver<Option<Instant>>,
) -> Result<Option<T>> {
    tokio::select! {
        biased;
        result = wait(receiver) => {
            result?;
            // The actual opening future is dropped before the caller joins its
            // retained native group; its owner guard starts cancellation.
            Ok(None)
        },
        result = opening => result.map(Some),
    }
}

#[cfg(test)]
#[path = "signals/tests.rs"]
mod tests;
