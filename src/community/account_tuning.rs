//! Trusted economic tuning on the same retained native account owner.
use super::*;
use cblc::accounting_ledger::WaitingPeriodTuning;

impl CommunityService {
    pub(crate) async fn tune_account_waiting_period(
        &mut self,
        expected_revision: u64,
        seconds: u64,
    ) -> Result<WaitingPeriodTuning> {
        let runtime = self.accounts.clone().ok_or(Error::Unavailable)?;
        crate::service::with_live_clock(async {
            let tuning = self
                .facade
                .tune_account_waiting_period(expected_revision, seconds, || runtime.native_time())
                .await
                .map_err(|_| Error::Reconcile)?;
            runtime.observe()?;
            if expected_revision.checked_add(1) != Some(tuning.revision)
                || tuning.seconds != seconds
            {
                return Err(Error::Reconcile);
            }
            // Refresh each actual publication owner; never reconstruct a
            // material, change an admission digest, or reset the native ledger.
            self.refresh_root_board(runtime.observe()?)
                .await
                .map_err(|_| Error::Reconcile)?;
            self.facade
                .publish_account_material(&runtime.period_key, || runtime.native_time())
                .await
                .map_err(|_| Error::Reconcile)?;
            runtime.observe()?;
            self.refresh(runtime.observe()?)
                .await
                .map_err(|_| Error::Reconcile)?;
            let policy = self.facade.policy().lock().await;
            let now = runtime.observe()?;
            let epoch = policy.epoch(now).await.map_err(|_| Error::Reconcile)?;
            let now = runtime.observe()?;
            let ring = policy.key_ring().map_err(|_| Error::Reconcile)?;
            if self.public.policy_epoch != epoch || self.public.key_ring != ring.to_cbor() {
                return Err(Error::Reconcile);
            }
            let balance = self.public.balance.as_ref().ok_or(Error::Reconcile)?;
            let signed = ring
                .verify(balance, csgn::Kind::SettingsSnapshot, now)
                .map_err(|_| Error::Reconcile)?;
            let material: cblc::publication::PublicVerifierMaterial =
                serde_json::from_slice(signed.payload()).map_err(|_| Error::Reconcile)?;
            material
                .validate_at(&self.config.community, now)
                .map_err(|_| Error::Reconcile)?;
            // Publication revision belongs to Policy; it is distinct from the
            // returned native tuning revision. Compare the actual economics.
            if material.policy_epoch != epoch
                || material.policy_digest != tuning.policy_digest
                || material.policy.account.abandon_after != tuning.seconds
            {
                return Err(Error::Reconcile);
            }
            let material_deadline = material.record_epoch.as_ref().map_or(
                material.policy.account.policy_valid_until,
                |record| {
                    record
                        .expires_at
                        .min(material.policy.account.policy_valid_until)
                },
            );
            let mut deadline = material_deadline;
            for bytes in [
                &self.public.manifest,
                &self.public.settings,
                &self.public.schema,
                &self.public.communities,
                &self.public.revocations,
                balance,
            ]
            .into_iter()
            .chain(self.public.root_board.iter())
            {
                let signed = ring
                    .verify(bytes, csgn::Kind::SettingsSnapshot, now)
                    .map_err(|_| Error::Reconcile)?;
                deadline = deadline.min(signed.valid_until());
            }
            if runtime.observe()? >= deadline {
                return Err(Error::Reconcile);
            }
            Ok(tuning)
        })
        .await
        .map_err(|_| Error::Reconcile)
    }
}
