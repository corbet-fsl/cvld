//! The door binds the original membership confirmation to one exact live session.
use super::*;

pub(super) struct PendingSelfBan {
    value: cmbr::PendingSelfBanConfirmation,
    pub(super) session_id: [u8; 32],
    pub(super) credential: ckyh::CredentialID,
    pub(super) until: u64,
    observed: u64,
}

impl CommunityService {
    fn self_ban_time(&self, floor: u64, until: u64) -> Result<u64> {
        let now = self.clock.now();
        if now < floor || now >= until || now > i64::MAX as u64 {
            return Err(Error::Unauthorized);
        }
        crate::service::publication::expires_at(until)?;
        Ok(now)
    }

    pub async fn self_ban_begin(
        &mut self,
        bearer: &str,
        admitted_at: u64,
    ) -> Result<SelfBanChallenge> {
        let now = self.self_ban_time(admitted_at, u64::MAX)?;
        let (grant, auth) = self.authenticate(bearer, now).await?;
        let now = self.self_ban_time(now, grant.expires)?;
        let until = now.saturating_add(300).min(grant.expires);
        self.self_bans
            .retain(|_, pending| pending.session_id != grant.session_id);
        // The authenticated membership owner supplies the pseudonym. A UUID or
        // caller-selected identity can never become the order's subject.
        let row = crate::service::at(now, self.facade.membership().resume(&auth))
            .await
            .map_err(Error::Refused.redact())?;
        let now = self.self_ban_time(now, until)?;
        let order = clbs::Order {
            community: self.config.community.clone(),
            id: uuid::Uuid::new_v4().to_string(),
            subject: row.subject().into(),
            reference: "member-confirmed-termination".into(),
            entered_by: row.subject().into(),
            kind: clbs::OrderKind::SelfBan,
            scope: clbs::Scope::Member,
        };
        let (options, value) = crate::service::at(
            now,
            self.facade
                .membership()
                .begin_self_ban_confirmation(&auth, order, until as i64),
        )
        .await
        .map_err(Error::Refused.redact())?;
        let observed = self.self_ban_time(now, until)?;
        let ceremony = token();
        let options = serde_json::to_value(options).map_err(Error::Unavailable.redact())?;
        self.self_bans.insert(
            ceremony.clone(),
            PendingSelfBan {
                value,
                session_id: grant.session_id,
                credential: grant.credential,
                until,
                observed,
            },
        );
        Ok(SelfBanChallenge {
            ceremony,
            intent: SelfBanIntent::PermanentCommunitySelfBan,
            warning: "This permanently ends this community membership. There is no undo, recovery or operator override, and this membership cannot be registered again.".into(),
            expires: until,
            options,
        })
    }

    pub async fn self_ban_finish(
        &mut self,
        bearer: &str,
        request: SelfBanConfirmation,
        admitted_at: u64,
    ) -> Result<()> {
        let now = self.self_ban_time(admitted_at, u64::MAX)?;
        let (grant, auth) = self.authenticate(bearer, now).await?;
        let pending = self
            .self_bans
            .get(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        if pending.session_id != grant.session_id || pending.credential != grant.credential {
            return Err(Error::Unauthorized);
        }
        let now = self.self_ban_time(now.max(pending.observed), pending.until)?;
        let pending = self
            .self_bans
            .remove(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        let confirmation = crate::service::at(
            now,
            self.facade.membership().finish_self_ban_confirmation(
                &auth,
                pending.value,
                request.credential,
            ),
        )
        .await
        .map_err(Error::Refused.redact())?;
        let now = self.self_ban_time(now, pending.until)?;
        let (current, auth) = self.authenticate(bearer, now).await?;
        let now = self.self_ban_time(now, pending.until)?;
        if current.session_id != grant.session_id
            || current.user != confirmation.member()
            || current.credential != *confirmation.credential_id()
        {
            return Err(Error::Unauthorized);
        }
        let signed = self.authority.authorize(confirmation).await?;
        let now = self.self_ban_time(now, pending.until)?;
        // clbs verifies the one-use immutable intent. Membership appends the
        // legal record and revocation notice in the same original transaction.
        crate::service::at(now, self.facade.membership().self_ban(&auth, &signed))
            .await
            .map_err(Error::Reconcile.redact())?;
        self.sessions
            .retain(|_, session| session.grant.user != grant.user);
        let live: std::collections::HashSet<_> = self
            .sessions
            .values()
            .map(|session| session.grant.session_id)
            .collect();
        self.additions
            .retain(|_, pending| live.contains(&pending.session_id));
        self.self_bans
            .retain(|_, pending| live.contains(&pending.session_id));
        self.facade
            .flush_revocations(self.clock.now())
            .await
            .map_err(Error::Reconcile.redact())?;
        self.refresh(self.clock.now())
            .await
            .map_err(Error::Reconcile.redact())
    }
}
