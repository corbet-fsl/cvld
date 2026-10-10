//! Fresh original passkey authentication can inspect a terminal outcome only.
use super::*;

pub(super) struct PendingStatus {
    value: cmbr::PendingSelfBanStatus,
    pub(super) until: u64,
    observed: u64,
}

impl CommunityService {
    fn self_ban_status_time(&self, observed: u64, until: u64) -> Result<u64> {
        let now = self.clock.now();
        if now < observed || now >= until || now > i64::MAX as u64 {
            return Err(Error::Unauthorized);
        }
        Ok(now)
    }

    pub async fn self_ban_status_begin(
        &mut self,
        admitted_at: u64,
    ) -> Result<SelfBanStatusChallenge> {
        crate::service::with_live_clock(async {
            let now = self.self_ban_status_time(admitted_at, u64::MAX)?;
            self.prune(now);
            if self.self_ban_statuses.len() >= self.config.pending_capacity {
                return Err(Error::Throttled);
            }
            let until = now
                .checked_add(300)
                .filter(|end| *end <= i64::MAX as u64)
                .ok_or(Error::Unavailable)?;
            let (options, value) = self
                .facade
                .membership()
                .begin_self_ban_status(until as i64)
                .await
                .map_err(Error::Refused.redact())?;
            let observed = self.self_ban_status_time(now, until)?;
            if !value.is_current(observed as i64) {
                return Err(Error::Unauthorized);
            }
            crate::service::publication::expires_at(until)?;
            let ceremony = token();
            let options = serde_json::to_value(options).map_err(Error::Unavailable.redact())?;
            self.self_ban_statuses.insert(
                ceremony.clone(),
                PendingStatus {
                    value,
                    until,
                    observed,
                },
            );
            Ok(SelfBanStatusChallenge {
                ceremony,
                expires: until,
                options,
            })
        })
        .await
    }

    pub async fn self_ban_status_finish(
        &mut self,
        request: SelfBanConfirmation,
        admitted_at: u64,
    ) -> Result<SelfBanStatus> {
        crate::service::with_live_clock(async {
            let pending = self
                .self_ban_statuses
                .remove(&request.ceremony)
                .ok_or(Error::Unauthorized)?;
            let now =
                self.self_ban_status_time(admitted_at.max(pending.observed), pending.until)?;
            crate::service::publication::expires_at(pending.until)?;
            let status = self
                .facade
                .membership()
                .finish_self_ban_status(pending.value, request.credential)
                .await
                .map_err(Error::Reconcile.redact())?;
            let completed = self.self_ban_status_time(now, pending.until)?;
            if !status.is_current(completed as i64) {
                return Err(Error::Reconcile);
            }
            Ok(SelfBanStatus {
                self_banned: status.self_banned,
            })
        })
        .await
    }
}
