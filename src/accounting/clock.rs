//! One private clock floor joins native effects and host response publication.
use crate::{
    error::{Error, Result},
    service::Clock,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

pub(crate) struct AccountRuntime {
    clock: Arc<dyn Clock>,
    observed: AtomicU64,
    invalid: AtomicBool,
    pub(crate) maximum_request_bytes: usize,
    pub(crate) period_key: String,
}
impl AccountRuntime {
    pub(crate) fn new(
        clock: Arc<dyn Clock>,
        durable_floor: u64,
        maximum_request_bytes: usize,
        period_key: String,
    ) -> Result<Self> {
        let value = Self {
            clock,
            observed: AtomicU64::new(durable_floor),
            invalid: AtomicBool::new(false),
            maximum_request_bytes,
            period_key,
        };
        value.observe()?;
        Ok(value)
    }
    pub(crate) fn floor(&self) -> u64 {
        self.observed.load(Ordering::Acquire)
    }
    /// Use this SAME observer in the native service, Policy publication and
    /// final host check. No request can supply or reset an observation.
    pub(crate) fn observe(&self) -> Result<u64> {
        if self.invalid.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        let now = self.clock.now();
        if now == 0 || now > ((1u64 << 53) - 1) {
            self.invalid.store(true, Ordering::Release);
            return Err(Error::Unavailable);
        }
        if now < self.observed.fetch_max(now, Ordering::AcqRel) {
            self.invalid.store(true, Ordering::Release);
            return Err(Error::Unavailable);
        }
        if self.invalid.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        Ok(now)
    }
    pub(crate) fn native_time(&self) -> u64 {
        self.observe().unwrap_or(0)
    }
}
impl Clock for AccountRuntime {
    fn now(&self) -> u64 {
        // Publication's exclusive deadline always rejects this sentinel,
        // including a context whose raw clock has already regressed to zero.
        self.observe().unwrap_or(u64::MAX)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
