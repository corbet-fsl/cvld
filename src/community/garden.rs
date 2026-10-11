//! Separate garden sessions, backed by current original membership roles.
use super::*;

mod commit;
pub(crate) use commit::GardenCommit;

pub(super) fn public_role(role: cmbr::Role) -> Role {
    match role {
        cmbr::Role::Member => Role::Member,
        cmbr::Role::Admin => Role::Admin,
        cmbr::Role::Root => Role::Root,
    }
}

impl CommunityService {
    pub(crate) async fn current_member_role(&self, bearer: &str, now: u64) -> Result<MemberRole> {
        crate::service::with_live_clock(async {
            let (grant, auth) = self.authenticate_current(bearer, now).await?;
            let mut lease = self
                .facade
                .membership()
                .role_until(&auth, grant.expires)
                .await
                .map_err(Error::Refused.redact())?;
            self.facade
                .membership()
                .check_role(&mut lease)
                .await
                .map_err(Error::Refused.redact())?;
            let observed = self.clock.now();
            if observed < now || !lease.is_current(observed) {
                return Err(Error::Unauthorized);
            }
            Ok(MemberRole {
                member: lease.member().into(),
                role: public_role(lease.role()),
            })
        })
        .await
    }
    pub(crate) async fn assign_current_role(
        &self,
        bearer: &str,
        request: SetMemberRole,
        now: u64,
    ) -> Result<()> {
        crate::service::with_live_clock(async {
            let (grant, auth) = self.authenticate_garden_current(bearer, now).await?;
            let role = match request.role {
                Role::Member => cmbr::Role::Member,
                Role::Admin => cmbr::Role::Admin,
                Role::Root => cmbr::Role::Root,
            };
            self.facade
                .membership()
                .set_member_role(&auth, &request.member, role, now, grant.expires)
                .await
                .map_err(|error| match error {
                    cmbr::Error::Unavailable => Error::Reconcile,
                    _ => Error::Refused,
                })?;
            // Successful self-demotion intentionally changes the role. The
            // original leaf checked key/legal owners; the outer mutex retains
            // this exact host session map throughout the operation.
            let observed = self.clock.now();
            let current = self.sessions.get(bearer).ok_or(Error::Reconcile)?;
            if !current.garden
                || !Arc::ptr_eq(&auth, &current.authentication)
                || grant.session_id != current.grant.session_id
                || grant.credential != current.grant.credential
                || observed < now
                || observed >= grant.expires
            {
                return Err(Error::Reconcile);
            }
            Ok(())
        })
        .await
    }

    /// A temporary original member lease is released before returning. The
    /// privileged owner then acquires Policy before its own member lease.
    pub(crate) async fn authenticate_garden_current(
        &self,
        bearer: &str,
        now: u64,
    ) -> Result<(Grant, Arc<ckyh::Authentication>)> {
        let session = self
            .sessions
            .get(bearer)
            .filter(|session| {
                session.garden
                    && session.started <= now
                    && now < session.grant.expires
                    && session.grant.credential == *session.authentication.credential_id()
            })
            .ok_or(Error::Unauthorized)?;
        let lease = self
            .garden_lease(&session.authentication, now, session.grant.expires)
            .await?;
        let completed = self.clock.now();
        if completed < now || !lease.is_current(completed) {
            return Err(Error::Unauthorized);
        }
        let mut grant = session.grant.clone();
        grant.role = public_role(lease.role());
        grant.expires = grant.expires.min(lease.valid_until());
        Ok((grant, session.authentication.clone()))
    }

    pub(crate) async fn authenticate_garden(
        &mut self,
        bearer: &str,
        now: u64,
    ) -> Result<(Grant, Arc<ckyh::Authentication>)> {
        self.prune(now);
        self.authenticate_garden_current(bearer, now).await
    }

    pub(crate) async fn garden_lease(
        &self,
        authentication: &ckyh::Authentication,
        started: u64,
        until: u64,
    ) -> Result<cmbr::RoleLease> {
        crate::service::with_live_clock(async {
            let lease = self
                .facade
                .membership()
                .role_until(authentication, until)
                .await
                .map_err(Error::Forbidden.redact())?;
            let observed = self.clock.now();
            if observed < started || !lease.is_current(observed) {
                return Err(Error::Unauthorized);
            }
            match lease.role() {
                cmbr::Role::Root => {}
                cmbr::Role::Admin if self.config.community != "root" => {}
                _ => return Err(Error::Forbidden),
            }
            Ok(lease)
        })
        .await
    }
}
