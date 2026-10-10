//! A login ceremony cannot authorize an irreversible holder-requested suspension.
use super::*;
use crate::service::Clock;
use std::time::{Duration, Instant};

pub(super) struct PendingSelfBan {
    state: PendingAuthentication,
    pub(super) session_id: [u8; 32],
    pub(super) authorizer: ckyh::CredentialID,
    pub(super) until: u64,
    deadline: Instant,
}

/// Only a completed, purpose-specific, UV-required ceremony constructs this.
pub(crate) struct ConfirmedSelfBan {
    user: Uuid,
    session_id: [u8; 32],
    authorizer: ckyh::CredentialID,
    until: u64,
    observed: u64,
    deadline: Instant,
}
impl ConfirmedSelfBan {
    pub(crate) fn user(&self) -> Uuid {
        self.user
    }

    pub(crate) fn validate(&self, grant: &Grant, observed: u64, clock: &dyn Clock) -> Result<u64> {
        if grant.user != self.user
            || grant.session_id != self.session_id
            || grant.credential != self.authorizer
            || Instant::now() >= self.deadline
        {
            return Err(Error::Unauthorized);
        }
        let now = fresh(
            clock,
            self.observed.max(observed),
            self.until.min(grant.expires),
        )?;
        if Instant::now() >= self.deadline {
            return Err(Error::Unauthorized);
        }
        Ok(now)
    }
}

fn fresh(clock: &dyn Clock, floor: u64, until: u64) -> Result<u64> {
    let now = clock.now();
    if now < floor || now >= until {
        return Err(Error::Unauthorized);
    }
    Ok(now)
}

impl Auth {
    pub(crate) async fn begin_global_self_ban(
        &mut self,
        token: &str,
        now: u64,
        clock: &dyn Clock,
    ) -> Result<SelfBanChallenge> {
        let grant = self.authenticate(token, now).await?;
        if grant.role != Role::Member || self.operator.is_some() {
            return Err(Error::Forbidden);
        }
        let observed = fresh(clock, now, grant.expires)?;
        let until = observed.saturating_add(300).min(grant.expires);
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(until - observed))
            .ok_or(Error::Unauthorized)?;
        // One purpose-specific ceremony per live session bounds RAM by the
        // existing session cap. Replacement cannot affect another session.
        self.self_bans
            .retain(|_, p| p.session_id != grant.session_id);
        let keys = self.passkeys.clone();
        let credential = grant.credential.clone();
        let (options, state) = tokio::task::spawn_blocking(move || {
            keys.start_authentication_for(grant.user, &credential)
        })
        .await
        .map_err(Error::Unavailable.redact())?
        .map_err(Error::Unauthorized.redact())?;
        fresh(clock, observed, until)?;
        if Instant::now() >= deadline {
            return Err(Error::Unauthorized);
        }
        crate::service::publication::expires_at(until)?;
        let ceremony = super::token();
        let options = serde_json::to_value(options).map_err(Error::Unavailable.redact())?;
        self.self_bans.insert(
            ceremony.clone(),
            PendingSelfBan {
                state,
                session_id: grant.session_id,
                authorizer: grant.credential,
                until,
                deadline,
            },
        );
        Ok(SelfBanChallenge {
            ceremony,
            intent: SelfBanIntent::PermanentGlobalSelfBan,
            warning: "This permanently ends access through this wallet. There is no undo, recovery or operator override. Verified identities cannot be reused to return.".into(),
            expires: until,
            options,
        })
    }

    pub(crate) async fn finish_global_self_ban(
        &mut self,
        token: &str,
        request: SelfBanConfirmation,
        now: u64,
        clock: &dyn Clock,
    ) -> Result<ConfirmedSelfBan> {
        let grant = self.authenticate(token, now).await?;
        let pending = self
            .self_bans
            .get(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        if grant.role != Role::Member
            || self.operator.is_some()
            || pending.session_id != grant.session_id
            || pending.authorizer != grant.credential
            || Instant::now() >= pending.deadline
        {
            return Err(Error::Unauthorized);
        }
        let observed = fresh(clock, now, pending.until)?;
        let pending = self
            .self_bans
            .remove(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        crate::service::publication::expires_at(pending.until)?;
        let keys = self.passkeys.clone();
        let authentication = tokio::task::spawn_blocking(move || {
            keys.finish_authentication(pending.state, &request.credential)
        })
        .await
        .map_err(Error::Unavailable.redact())?
        .map_err(Error::Unauthorized.redact())?;
        let completed = fresh(clock, observed, pending.until)?;
        if authentication.member() != grant.user
            || authentication.credential_id() != &grant.credential
            || Instant::now() >= pending.deadline
        {
            return Err(Error::Unauthorized);
        }
        Ok(ConfirmedSelfBan {
            user: grant.user,
            session_id: grant.session_id,
            authorizer: grant.credential,
            until: pending.until,
            observed: completed,
            deadline: pending.deadline,
        })
    }
}
