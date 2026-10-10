//! Original member authority and current caller policy before each paid phase.
use super::*;
use crate::payments::Owner;
use cgts::Gate;
pub(super) struct PaymentClock(pub Arc<dyn Clock>);
impl cpmt::cost::Clock for PaymentClock {
    fn now(&self) -> u64 {
        self.0.now()
    }
}

pub(crate) struct PaymentAuthorization {
    pub owner: Owner,
    pub observed: u64,
    pub session_expires: u64,
    pub policy_epoch: u64,
    pub policy_revision: u64,
}
impl CommunityService {
    fn payment_time(&self, floor: u64, until: u64) -> Result<u64> {
        let now = self.clock.now();
        if now < floor || now >= until || now > i64::MAX as u64 {
            return Err(Error::Unauthorized);
        }
        Ok(now)
    }
    /// Runs under the community lease. The action handler drops that lease
    /// before awaiting PaymentHost execution; each transport phase reacquires
    /// it only for these original-session and current policy checks.
    pub(crate) async fn payment_authorization(
        &mut self,
        token: &str,
        expected: Option<&Owner>,
        policy: Option<(u64, u64)>,
        floor: u64,
        until: u64,
    ) -> Result<PaymentAuthorization> {
        crate::service::with_live_clock(async {
            let config = self.config.payments.as_ref().ok_or(Error::Refused)?.clone();
            let mut observed = self.payment_time(floor, until)?;
            let (grant, authentication) = self.authenticate(token, observed).await?;
            let until = until.min(grant.expires);
            observed = self.payment_time(observed, until)?;
            if grant.role != Role::Member
                || grant.user != authentication.member()
                || grant.credential != *authentication.credential_id()
            {
                return Err(Error::Unauthorized);
            }
            let row = self
                .facade
                .membership()
                .resume(&authentication)
                .await
                .map_err(Error::Unauthorized.redact())?;
            observed = self.payment_time(observed, until)?;
            let owner = Owner {
                subject: row.subject().into(),
                user: grant.user,
                session: grant.session_id,
                credential: grant.credential.clone(),
            };
            if expected.is_some_and(|expected| expected != &owner) {
                return Err(Error::Unauthorized);
            }
            let snapshot = self
                .facade
                .snapshot(observed)
                .await
                .map_err(Error::Refused.redact())?;
            observed = self.payment_time(observed, until)?;
            if observed >= snapshot.valid_until
                || policy.is_some_and(|(epoch, revision)| {
                    epoch != snapshot.rules.policy_epoch || revision != snapshot.rules.revision
                })
            {
                return Err(Error::Refused);
            }
            let gate = cgts::payments::PaidAccessGate::new(
                config.gate.clone(),
                config.provider.clone(),
                config.access.level.clone(),
                true,
            )
            .map_err(Error::Invalid.redact())?;
            let enabled = self
                .facade
                .gates()
                .steps(
                    cgts::Context {
                        snapshot: &snapshot.rules,
                        subject: &owner.subject,
                        action: cmty::ADMISSION_ACTION,
                        now: observed as i64,
                    },
                    &[gate.descriptor()],
                )
                .await
                .map_err(Error::Refused.redact())?;
            observed = self.payment_time(observed, until)?;
            if enabled.len() != 1 {
                return Err(Error::Refused);
            }
            // Current key/session after all policy/legal waits, immediately
            // before returning the exact observation used by transport.
            let (current, current_auth) = self.authenticate(token, observed).await?;
            observed = self.payment_time(observed, until.min(current.expires))?;
            if current.user != owner.user
                || current.session_id != owner.session
                || current.credential != owner.credential
                || current_auth.member() != owner.user
                || current_auth.credential_id() != &owner.credential
            {
                return Err(Error::Unauthorized);
            }
            Ok(PaymentAuthorization {
                owner,
                observed,
                session_expires: grant.expires.min(current.expires),
                policy_epoch: snapshot.rules.policy_epoch,
                policy_revision: snapshot.rules.revision,
            })
        })
        .await
    }
}
