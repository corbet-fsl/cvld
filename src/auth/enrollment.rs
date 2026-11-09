//! The original wallet ceremony owns UUID, challenge and immutable seed.
use super::*;
use crate::service::Clock;
use std::time::Instant;

mod provenance;

#[cfg(test)]
pub(super) struct FixedClock(pub(super) u64);
#[cfg(test)]
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}
pub(super) fn fresh(clock: &dyn Clock, floor: u64, until: u64, deadline: Instant) -> Result<u64> {
    use crate::refusal::{Reason, refuse};
    let now = clock.now();
    if now < floor {
        return Err(refuse(Reason::ClockBehind));
    }
    if now >= until {
        return Err(refuse(Reason::SessionExpired));
    }
    if Instant::now() >= deadline {
        return Err(refuse(Reason::DeadlinePassed));
    }
    if i64::try_from(now)
        .ok()
        .and_then(|n| chrono::DateTime::from_timestamp(n, 0))
        .is_none()
    {
        return Err(refuse(Reason::TimeInvalid));
    }
    Ok(now)
}
pub(super) fn pending_time<T>(pending: &Pending<T>, floor: u64, clock: &dyn Clock) -> Result<u64> {
    fresh(
        clock,
        floor.max(pending.observed),
        pending.expires,
        pending.deadline,
    )
}

impl Auth {
    pub(crate) async fn continue_initial_registration(
        &mut self,
        request: GlobalInitialRegistrationContinue,
        admitted_at: u64,
        clock: &dyn Clock,
    ) -> Result<InitialCeremony> {
        if self.role != Role::Member || self.operator.is_some() {
            return Err(Error::Forbidden);
        }
        if request.seed == [0; 32] {
            return Err(Error::Invalid);
        }
        self.prune(admitted_at);
        let pending = self
            .registrations
            .get_mut(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        let now = pending_time(pending, admitted_at, clock)?;
        // Retain EVERY valid observation before an early conflict or await.
        // Cancelling challenge preparation cannot erase this pending's floor.
        pending.observed = now;
        let user = pending.user;
        let expires = pending.expires;
        let deadline = pending.deadline;
        crate::service::publication::expires_at(expires)?;
        let (options, replacement) = if let Some((seed, options)) = &pending.initial {
            if *seed != request.seed {
                return Err(Error::Refused);
            }
            (options.clone(), None)
        } else {
            let keys = self.passkeys.clone();
            let seed = request.seed;
            let (options, state) = tokio::task::spawn_blocking(move || {
                if !keys.list(user)?.is_empty() {
                    return Err(ckyh::Error::DuplicateCredential);
                }
                keys.start_initial_registration(user, Some(seed))
            })
            .await
            .map_err(Error::Unavailable.redact())?
            .map_err(Error::Refused.redact())?;
            (
                serde_json::to_value(options).map_err(Error::Unavailable.redact())?,
                Some(state),
            )
        };
        let checked_at = fresh(clock, now, expires, deadline)?;
        // Auth's exclusive mutable owner serializes continue against finish.
        // Cancellation retains the observation floor but installs no challenge.
        let pending = self
            .registrations
            .get_mut(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        if let Some(state) = replacement {
            pending.state = state;
            pending.initial = Some((request.seed, options.clone()));
        }
        pending.observed = checked_at;
        Ok(InitialCeremony {
            ceremony: request.ceremony,
            user: user.to_string(),
            options,
            checked_at,
            expires_at: expires,
        })
    }
}
