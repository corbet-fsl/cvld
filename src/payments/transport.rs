//! Original x402 transport boundary with a trusted asynchronous phase guard.
use cpmt::cost::Clock as _;
use cpmt::payments::{Error, Result};
use crpt::facilitator::{DispatchGuard, Exchange, Transport};
use std::{future::Future, pin::Pin, sync::Arc};
use x402_types::proto::{
    SettleRequest, SettleResponse, SupportedResponse, VerifyRequest, VerifyResponse,
};

type Pending<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The host checks the exact original live subject/key/session and configured
/// policy/terms after waits, before every billable protocol phase. Return the
/// latest trusted observation; transport preserves that floor across phases.
pub trait PhaseAuthority: Send + Sync {
    fn check(&self) -> Pending<'_, Result<u64>>;
}

/// Only the external protocol transport can be injected by trusted Rust code.
/// Member JSON cannot supply this object or a successful payment fact.
pub trait TrustedTransport: Send + Sync {
    fn supported<'a>(
        &'a self,
        guard: &'a DispatchGuard<'a>,
    ) -> Pending<'a, Exchange<SupportedResponse>>;
    fn verify<'a>(
        &'a self,
        request: &'a VerifyRequest,
        guard: &'a DispatchGuard<'a>,
    ) -> Pending<'a, Exchange<VerifyResponse>>;
    fn settle<'a>(
        &'a self,
        request: &'a SettleRequest,
        guard: &'a DispatchGuard<'a>,
    ) -> Pending<'a, Exchange<SettleResponse>>;
}
impl<T: Transport> TrustedTransport for T {
    fn supported<'a>(
        &'a self,
        guard: &'a DispatchGuard<'a>,
    ) -> Pending<'a, Exchange<SupportedResponse>> {
        Box::pin(self.supported_details(guard))
    }
    fn verify<'a>(
        &'a self,
        request: &'a VerifyRequest,
        guard: &'a DispatchGuard<'a>,
    ) -> Pending<'a, Exchange<VerifyResponse>> {
        Box::pin(self.verify_details(request, guard))
    }
    fn settle<'a>(
        &'a self,
        request: &'a SettleRequest,
        guard: &'a DispatchGuard<'a>,
    ) -> Pending<'a, Exchange<SettleResponse>> {
        Box::pin(self.settle_details(request, guard))
    }
}

#[derive(Clone)]
pub struct AnyTransport(pub Arc<dyn TrustedTransport>);

/// A registered adapter uses one active, single-use host ceremony at a time.
/// The host serializes execution. The lease is removed on cancellation/drop;
/// durable Journal uncertainty remains authoritative.
#[derive(Clone)]
pub(crate) struct GuardedTransport {
    pub wire: AnyTransport,
    active: Arc<std::sync::Mutex<Option<Active>>>,
}
struct Active {
    authority: Arc<dyn PhaseAuthority>,
    observed: u64,
    until: u64,
    started: std::time::Instant,
    lifetime: std::time::Duration,
    clock: Arc<super::ObservedClock>,
}
pub(crate) struct Lease {
    active: Arc<std::sync::Mutex<Option<Active>>>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            *active = None;
        }
    }
}
impl GuardedTransport {
    pub fn new(wire: AnyTransport) -> Self {
        Self {
            wire,
            active: Arc::default(),
        }
    }
    pub fn begin(
        &self,
        authority: Arc<dyn PhaseAuthority>,
        observed: u64,
        until: u64,
        started: std::time::Instant,
        lifetime: std::time::Duration,
        clock: Arc<super::ObservedClock>,
    ) -> Result<Lease> {
        let mut active = self.active.lock().map_err(|_| Error::Rejected)?;
        if active.is_some() {
            return Err(Error::Conflict);
        }
        *active = Some(Active {
            authority,
            observed,
            until,
            started,
            lifetime,
            clock,
        });
        Ok(Lease {
            active: self.active.clone(),
        })
    }
    pub fn observed(&self) -> Result<u64> {
        self.active
            .lock()
            .map_err(|_| Error::Rejected)?
            .as_ref()
            .map(|active| active.observed)
            .ok_or(Error::Rejected)
    }
    async fn current(&self, guard: &DispatchGuard<'_>) -> Result<()> {
        guard.check()?;
        let (authority, floor) = {
            let active = self.active.lock().map_err(|_| Error::Rejected)?;
            let active = active.as_ref().ok_or(Error::Rejected)?;
            (active.authority.clone(), active.observed)
        };
        let now = authority.check().await?;
        let mut active = self.active.lock().map_err(|_| Error::Rejected)?;
        let active = active.as_mut().ok_or(Error::Rejected)?;
        if !Arc::ptr_eq(&authority, &active.authority) || now < floor || now < active.observed {
            return Err(Error::Expired);
        }
        let completed = active.clock.now();
        if !active.clock.valid()
            || completed < now
            || completed >= active.until
            || active.started.elapsed() >= active.lifetime
        {
            return Err(Error::Expired);
        }
        active.observed = completed;
        guard.check()
    }
}
fn refused<T>(error: Error) -> Exchange<T> {
    Exchange {
        result: Err(error),
        upstream: Vec::new(),
    }
}
impl Transport for GuardedTransport {
    async fn supported_details(&self, guard: &DispatchGuard<'_>) -> Exchange<SupportedResponse> {
        if let Err(error) = self.current(guard).await {
            return refused(error);
        }
        self.wire.0.supported(guard).await
    }
    async fn verify_details(
        &self,
        request: &VerifyRequest,
        guard: &DispatchGuard<'_>,
    ) -> Exchange<VerifyResponse> {
        if let Err(error) = self.current(guard).await {
            return refused(error);
        }
        self.wire.0.verify(request, guard).await
    }
    async fn settle_details(
        &self,
        request: &SettleRequest,
        guard: &DispatchGuard<'_>,
    ) -> Exchange<SettleResponse> {
        if let Err(error) = self.current(guard).await {
            return refused(error);
        }
        self.wire.0.settle(request, guard).await
    }
}
