//! The exact original session survives queueing, never its removal or replacement.
use super::*;
use crate::auth::Grant;

impl Owner {
    pub(in crate::community) fn role_lease(
        &self,
        authentication: Arc<ckyh::Authentication>,
        grant: Grant,
        started: u64,
    ) -> Arc<dyn cmbr::RoleSession> {
        Arc::new(RoleLease {
            active: self.0.clone(),
            authentication,
            grant,
            started,
        })
    }
}
struct RoleLease {
    active: Arc<AtomicBool>,
    authentication: Arc<ckyh::Authentication>,
    grant: Grant,
    started: u64,
}
impl cmbr::RoleSession for RoleLease {
    fn valid_until(&self) -> u64 {
        self.grant.expires
    }
    fn check(&self, authentication: &ckyh::Authentication, observed: u64) -> cmbr::Result<()> {
        // Membership owns the genuine live observed-clock sample and brackets
        // this synchronous check; no optional runtime or second clock is needed.
        if !self.active.load(Ordering::Acquire)
            || observed < self.started
            || observed >= self.grant.expires
            || authentication.community() != self.authentication.community()
            || authentication.member() != self.authentication.member()
            || authentication.credential_id() != self.authentication.credential_id()
            || authentication.member() != self.grant.user
            || *authentication.credential_id() != self.grant.credential
            || !self.active.load(Ordering::Acquire)
        {
            return Err(cmbr::Error::Identity);
        }
        Ok(())
    }
}
