//! Invalidation follows the actual session owner even after HTTP cancellation.
use crate::accounting::clock::AccountRuntime;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

mod role;

pub(super) struct Owner(Arc<AtomicBool>);

impl Default for Owner {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        // SessionState is never cloned. Removal, expiry pruning, replacement
        // and service destruction all invalidate this exact original session.
        self.0.store(false, Ordering::Release);
    }
}

impl Owner {
    pub(super) fn lease(
        &self,
        started: u64,
        expires: u64,
        runtime: Arc<AccountRuntime>,
    ) -> Arc<dyn cmty::AccountSession> {
        Arc::new(Lease {
            active: self.0.clone(),
            started,
            expires,
            runtime,
        })
    }
}

struct Lease {
    active: Arc<AtomicBool>,
    started: u64,
    expires: u64,
    runtime: Arc<AccountRuntime>,
}

impl cmty::AccountSession for Lease {
    fn valid_until(&self) -> u64 {
        self.expires
    }

    /// Evaluated at `observed` (commit authorities evaluate at the observed time):
    /// the live clock must not lie before it, and only the session's own end in
    /// (observed, now] refuses; a plain later second does not.
    fn check(&self, observed: u64) -> cmty::Result<()> {
        if observed < self.started
            || observed >= self.expires
            || !self.active.load(Ordering::Acquire)
        {
            return Err(cmty::Error::Membership);
        }
        let now = self.runtime.observe().map_err(|_| cmty::Error::Time)?;
        if now < observed || now >= self.expires || !self.active.load(Ordering::Acquire) {
            return Err(cmty::Error::Membership);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
