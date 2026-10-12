//! Fresh user-verifying assertions that authorize one account-authority action.
//!
//! A challenge is bound to the member, the live session and its credential, the
//! host (community scope) and the exact action with its target. It is single
//! use: any attempt to complete it removes it, whether the proof is right or
//! not, so a replay or a probe for another action never finds a live challenge.
use crate::{
    api::{StepUpAction, StepUpChallenge},
    auth::Grant,
    error::{Error, Result},
    service::Clock,
};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// Seconds a challenge stays valid at most.
pub(crate) const LIFETIME: u64 = 60;

struct Pending<S> {
    state: S,
    session_id: [u8; 32],
    credential: ckyh::CredentialID,
    host: String,
    action: StepUpAction,
    until: u64,
    deadline: Instant,
}

/// The host (community scope) and exact action a challenge is bound to.
#[derive(Clone, Copy)]
pub(crate) struct Binding<'a> {
    pub(crate) host: &'a str,
    pub(crate) action: &'a StepUpAction,
}

/// The deadlines of one challenge, fixed before its ceremony state exists.
pub(crate) struct Plan {
    pub(crate) observed: u64,
    pub(crate) until: u64,
    deadline: Instant,
}

/// The deadlines of a removed challenge, kept until its assertion is verified.
pub(crate) struct Receipt {
    observed: u64,
    until: u64,
    deadline: Instant,
}

pub(crate) struct StepUps<S> {
    pending: HashMap<String, Pending<S>>,
}

impl<S> Default for StepUps<S> {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }
}

fn fresh(clock: &dyn Clock, floor: u64, until: u64) -> Result<u64> {
    let now = clock.now();
    if now < floor || now >= until {
        return Err(Error::Unauthorized);
    }
    Ok(now)
}

impl<S> StepUps<S> {
    /// One challenge per live session: a new one replaces the previous one.
    pub(crate) fn plan(&mut self, grant: &Grant, now: u64, clock: &dyn Clock) -> Result<Plan> {
        self.pending.retain(|_, p| p.until > now);
        self.pending.retain(|_, p| p.session_id != grant.session_id);
        let observed = fresh(clock, now, grant.expires)?;
        let until = observed.saturating_add(LIFETIME).min(grant.expires);
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(until - observed))
            .ok_or(Error::Unauthorized)?;
        Ok(Plan {
            observed,
            until,
            deadline,
        })
    }

    pub(crate) fn insert(
        &mut self,
        plan: Plan,
        grant: &Grant,
        binding: Binding<'_>,
        state: S,
        options: serde_json::Value,
        clock: &dyn Clock,
    ) -> Result<StepUpChallenge> {
        fresh(clock, plan.observed, plan.until)?;
        if Instant::now() >= plan.deadline {
            return Err(Error::Unauthorized);
        }
        crate::service::publication::expires_at(plan.until)?;
        let ceremony = crate::auth::token();
        self.pending.insert(
            ceremony.clone(),
            Pending {
                state,
                session_id: grant.session_id,
                credential: grant.credential.clone(),
                host: binding.host.to_owned(),
                action: binding.action.clone(),
                until: plan.until,
                deadline: plan.deadline,
            },
        );
        Ok(StepUpChallenge {
            ceremony,
            expires: plan.until,
            options,
        })
    }

    /// Remove the challenge and refuse unless it belongs to this exact session,
    /// host and action. The challenge is gone either way.
    pub(crate) fn take(
        &mut self,
        ceremony: &str,
        grant: &Grant,
        binding: Binding<'_>,
        now: u64,
        clock: &dyn Clock,
    ) -> Result<(S, Receipt)> {
        let pending = self.pending.remove(ceremony).ok_or(Error::Unauthorized)?;
        if pending.session_id != grant.session_id
            || pending.credential != grant.credential
            || pending.host != binding.host
            || &pending.action != binding.action
            || Instant::now() >= pending.deadline
        {
            return Err(Error::Unauthorized);
        }
        let observed = fresh(clock, now, pending.until)?;
        Ok((
            pending.state,
            Receipt {
                observed,
                until: pending.until,
                deadline: pending.deadline,
            },
        ))
    }

    /// Drop every challenge whose session is no longer live.
    pub(crate) fn retain_sessions(&mut self, live: &std::collections::HashSet<[u8; 32]>) {
        self.pending.retain(|_, p| live.contains(&p.session_id));
    }

    pub(crate) fn prune(&mut self, now: u64) {
        self.pending.retain(|_, p| p.until > now);
    }
}

impl Receipt {
    /// The assertion must come from this member's session credential, and the
    /// challenge must still be live when the check completes.
    pub(crate) fn complete(&self, verified: bool, clock: &dyn Clock) -> Result<()> {
        fresh(clock, self.observed, self.until)?;
        if !verified || Instant::now() >= self.deadline {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
