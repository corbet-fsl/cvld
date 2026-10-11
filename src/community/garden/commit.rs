//! Actual garden authority at the original rulebook/policy writer commit.
use super::*;

pub(crate) struct GardenCommit<'a> {
    community: &'a CommunityService,
    context: &'a crate::service::Context,
    lease: &'a mut cmbr::RoleLease,
    action: &'static str,
    cut: Option<u64>,
}
impl<'a> GardenCommit<'a> {
    pub(crate) fn new(
        community: &'a CommunityService,
        context: &'a crate::service::Context,
        lease: &'a mut cmbr::RoleLease,
        action: &'static str,
    ) -> Self {
        Self {
            community,
            context,
            lease,
            action,
            cut: None,
        }
    }

    fn session(&self, now: u64) -> cplc::crbk::Result<()> {
        let grant = self
            .context
            .grant
            .as_ref()
            .ok_or(cplc::crbk::Error::Storage)?;
        let token = self
            .context
            .token
            .as_deref()
            .ok_or(cplc::crbk::Error::Storage)?;
        let original = self
            .context
            .authentication
            .as_ref()
            .ok_or(cplc::crbk::Error::Storage)?;
        let current = self
            .community
            .sessions
            .get(token)
            .ok_or(cplc::crbk::Error::Storage)?;
        if !current.garden
            || !Arc::ptr_eq(original, &current.authentication)
            || current.grant.user != grant.user
            || current.grant.session_id != grant.session_id
            || current.grant.credential != grant.credential
            || grant.expires > current.grant.expires
            || now < current.started
            || now < self.context.now
            || now >= grant.expires
            || !self.lease.is_current(now)
        {
            return Err(cplc::crbk::Error::Storage);
        }
        Ok(())
    }
}
impl cplc::crbk::CommitGuard for GardenCommit<'_> {
    async fn check(&mut self) -> cplc::crbk::Result<()> {
        crate::service::with_live_clock(async {
            self.cut = None;
            let begun = self.community.clock.now();
            self.session(begun)?;
            let observed = self
                .community
                .facade
                .membership()
                .check_role_action(self.lease, self.action)
                .await
                .map_err(|_| cplc::crbk::Error::Storage)?;
            if observed != begun {
                return Err(cplc::crbk::Error::Storage);
            }
            self.cut = Some(observed);
            self.release()
        })
        .await
    }

    fn release(&mut self) -> cplc::crbk::Result<()> {
        let now = self.community.clock.now();
        if self.cut != Some(now) {
            return Err(cplc::crbk::Error::Storage);
        }
        self.session(now)
    }
}
