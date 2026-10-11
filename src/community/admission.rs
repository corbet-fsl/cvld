//! Exact originating session and observed floor retained across admission.
use super::*;
use crate::service::Context;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub(super) struct AdmissionSession {
    pub(super) authentication: Arc<ckyh::Authentication>,
    actual: Arc<dyn cmbr::RoleSession>,
    observed: AtomicU64,
    valid: AtomicBool,
}
impl cmbr::RoleSession for AdmissionSession {
    fn valid_until(&self) -> u64 {
        self.actual.valid_until()
    }
    fn check(&self, authentication: &ckyh::Authentication, observed: u64) -> cmbr::Result<()> {
        if !self.valid.load(Ordering::Acquire) {
            eprintln!("DIAG session invalid observed={observed}");
            return Err(cmbr::Error::Unavailable);
        }
        self.actual
            .check(authentication, observed)
            .inspect_err(|_| {
                self.valid.store(false, Ordering::Release);
            })?;
        let previous = self.observed.fetch_max(observed, Ordering::AcqRel);
        if observed < previous {
            eprintln!("DIAG session regress observed={observed} previous={previous}");
            self.valid.store(false, Ordering::Release);
            return Err(cmbr::Error::Unavailable);
        }
        if !self.valid.load(Ordering::Acquire) {
            return Err(cmbr::Error::Unavailable);
        }
        Ok(())
    }
}
impl AdmissionSession {
    pub(super) fn release(&self, observed: u64) -> Result<()> {
        cmbr::RoleSession::check(self, &self.authentication, observed).map_err(|e| {
            eprintln!(
                "DIAG admission release {e:?} observed={observed} line={}",
                line!()
            );
            Error::Reconcile
        })
    }
}
impl CommunityService {
    pub(super) fn admission_session(&self, ctx: &Context) -> Result<AdmissionSession> {
        let bearer = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
        let grant = ctx.grant.as_ref().ok_or(Error::Unauthorized)?;
        let authentication = ctx.authentication.as_ref().ok_or(Error::Unauthorized)?;
        let current = self.sessions.get(bearer).ok_or(Error::Unauthorized)?;
        if ctx.host != format!("api.{}.{}", self.config.community, self.config.domain)
            || current.garden
            || current.grant.session_id != grant.session_id
            || current.grant.user != grant.user
            || current.grant.credential != grant.credential
            || current.grant.expires != grant.expires
            || current.grant.role != grant.role
            || !Arc::ptr_eq(authentication, &current.authentication)
        {
            return Err(Error::Unauthorized);
        }
        let session = AdmissionSession {
            authentication: authentication.clone(),
            actual: current.authority.role_lease(
                authentication.clone(),
                grant.clone(),
                current.started,
            ),
            observed: AtomicU64::new(ctx.now),
            valid: AtomicBool::new(true),
        };
        cmbr::RoleSession::check(&session, authentication, ctx.now)
            .map_err(Error::Unauthorized.redact())?;
        Ok(session)
    }
}

#[cfg(all(test, feature = "development-gate"))]
#[path = "admission/tests.rs"]
mod tests;
