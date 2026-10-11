//! Trusted signer lifecycle on the configured native account owner.
use super::*;

impl CommunityService {
    pub(crate) async fn rotate_account_signer(&mut self, key: csgn::SecretKey) -> Result<()> {
        let runtime = self.accounts.clone().ok_or(Error::Unavailable)?;
        crate::service::with_live_clock(async {
            let mut policy = self.facade.policy().lock().await;
            let now = runtime.observe()?;
            // The original wiping key owner consumes this provisioned secret.
            // A failed rotation can already have committed durable signer state.
            policy
                .rotate(key, now)
                .await
                .map_err(|_| Error::Reconcile)?;
            runtime.observe()?;
            drop(policy);
            // The outer actual Community mutex remains held across all original
            // owner calls. No member route can use the half-rotated composition.
            let installed = self
                .facade
                .reconcile_account_admission_keys(|| runtime.native_time())
                .await
                .map_err(|_| Error::Reconcile)?;
            runtime.observe()?;
            self.refresh_root_board(runtime.observe()?)
                .await
                .map_err(|_| Error::Reconcile)?;
            self.facade
                .publish_account_material(&runtime.period_key, || runtime.native_time())
                .await
                .map_err(|_| Error::Reconcile)?;
            self.refresh(runtime.observe()?)
                .await
                .map_err(|_| Error::Reconcile)?;
            let now = runtime.observe()?;
            let policy = self.facade.policy().lock().await;
            let now = runtime.observe()?.max(now);
            let epoch = policy.epoch(now).await.map_err(|_| Error::Reconcile)?;
            let now = runtime.observe()?;
            let ring = policy.key_ring().map_err(|_| Error::Reconcile)?;
            let transitions = policy.key_transitions().map_err(|_| Error::Reconcile)?;
            if ring != &installed.policy_keys
                || transitions.last().map_or(0, |item| item.revision) != installed.revision
                || self.public.key_ring != installed.policy_keys.to_cbor()
                || self
                    .public
                    .key_transitions
                    .last()
                    .map_or(0, |item| item.revision)
                    != installed.revision
            {
                return Err(Error::Reconcile);
            }
            let balance = self.public.balance.as_ref().ok_or(Error::Reconcile)?;
            let signed_balance = ring
                .verify(balance, csgn::Kind::SettingsSnapshot, now)
                .map_err(|_| Error::Reconcile)?;
            let material: cblc::publication::PublicVerifierMaterial =
                serde_json::from_slice(signed_balance.payload()).map_err(|_| Error::Reconcile)?;
            if material.policy_epoch != epoch || self.public.policy_epoch != epoch {
                return Err(Error::Reconcile);
            }
            material
                .validate_at(&self.config.community, now)
                .map_err(|_| Error::Reconcile)?;
            let material_deadline = material.record_epoch.as_ref().map_or(
                material.policy.account.policy_valid_until,
                |epoch| {
                    epoch
                        .expires_at
                        .min(material.policy.account.policy_valid_until)
                },
            );
            let mut deadline = u64::MAX;
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
            if runtime.observe()? >= deadline.min(material_deadline) {
                return Err(Error::Reconcile);
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::Reconcile)
    }
}
