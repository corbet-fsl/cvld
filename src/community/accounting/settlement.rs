//! Anonymous outcome deposits: no member session, no subject, no contact data.
use super::*;

impl CommunityService {
    /// Stage one outcome deposit at the configured accounting owner. The owner verifies
    /// the deposit proof and the settlement-pass token and keeps the verified facts for
    /// the next daily cut; nothing here authenticates or names a member.
    pub(crate) async fn account_settlement_stage(
        &self,
        request: SettlementStage,
        admitted_at: u64,
    ) -> Result<SettlementStaged> {
        let runtime = self.accounts.as_ref().ok_or(Error::Unavailable)?;
        crate::service::with_live_clock(async {
            self.account_time(runtime, admitted_at.max(runtime.floor()), u64::MAX)?;
            let status = self
                .facade
                .stage_account_settlement(request.0)
                .await
                .map_err(|error| match error {
                    cmty::Error::Reconcile => Error::Reconcile,
                    cmty::Error::AccountUnavailable => Error::Unavailable,
                    _ => Error::Refused,
                })?;
            Ok(SettlementStaged(status))
        })
        .await
    }
}
