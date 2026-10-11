//! Current membership-backed garden actions; configured operators stay separate.
use super::*;

pub(super) fn operator_origins(host: &str) -> Result<Vec<ckyh::Url>> {
    let canonical = host.strip_prefix("api.admin.").ok_or(Error::Invalid)?;
    [
        format!("https://{host}"),
        format!("https://admin.{canonical}"),
        format!("https://vault.{canonical}"),
    ]
    .into_iter()
    .map(|origin| ckyh::Url::parse(&origin).map_err(Error::Invalid.redact()))
    .collect()
}

impl Door {
    // Policy comes before the original member lease. Configured platform roots
    // retain only their original platform actions; they cannot issue a source
    // credential or enter the membership garden.
    pub(crate) async fn policy_garden_lease(
        &self,
        ctx: &Context,
        community: &CommunityService,
    ) -> Result<Option<cmbr::RoleLease>> {
        let grant = ctx.grant.as_ref().ok_or(Error::Unauthorized)?;
        match ctx.authentication.as_deref() {
            Some(_) if self.is_garden(&ctx.host) => {
                let now = self.inner.clock.now();
                if now < ctx.now {
                    return Err(Error::Unauthorized);
                }
                let (current, exact) = community
                    .authenticate_garden_current(
                        ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                        now,
                    )
                    .await?;
                if current.user != grant.user
                    || current.session_id != grant.session_id
                    || current.credential != grant.credential
                    || !ctx
                        .authentication
                        .as_ref()
                        .is_some_and(|original| Arc::ptr_eq(original, &exact))
                {
                    return Err(Error::Unauthorized);
                }
                community
                    .garden_lease(&exact, now, current.expires.min(grant.expires))
                    .await
                    .map(Some)
            }
            None if !self.is_garden(&ctx.host) && grant.role == Role::Root => Ok(None),
            _ => Err(Error::Forbidden),
        }
    }
    pub(crate) async fn policy_garden_release(
        &self,
        ctx: &Context,
        community: &CommunityService,
        mut lease: Option<&mut cmbr::RoleLease>,
    ) -> Result<u64> {
        with_live_clock(async {
            let grant = ctx.grant.as_ref().ok_or(Error::Unauthorized)?;
            let floor = match lease.as_deref_mut() {
                Some(lease) => community
                    .facade
                    .membership()
                    .check_role(lease)
                    .await
                    .map_err(Error::Forbidden.redact())?,
                None => ctx.now,
            };
            let observed = self.inner.clock.now();
            if observed < ctx.now
                || observed < floor
                || observed >= grant.expires
                || lease
                    .as_ref()
                    .is_some_and(|lease| !lease.is_current(observed))
            {
                return Err(Error::Unauthorized);
            }
            Ok(observed)
        })
        .await
    }
    pub(crate) async fn member_role(&self, ctx: Context, _: Empty) -> Result<MemberRole> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .current_member_role(ctx.token.as_deref().ok_or(Error::Unauthorized)?, ctx.now)
            .await
    }
    pub(crate) async fn member_role_set(
        &self,
        ctx: Context,
        request: SetMemberRole,
    ) -> Result<Empty> {
        if !self.is_garden(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .assign_current_role(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                request,
                ctx.now,
            )
            .await?;
        Ok(Empty {})
    }
}
