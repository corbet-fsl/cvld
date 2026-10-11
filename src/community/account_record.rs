//! Retain and deliver only the actual worker's immutable common publication.
use super::*;
use axum::body::Bytes;
use cblc::accounting_ledger::record_epoch::RecordEpochPublication;

pub(super) struct PublishedRecord {
    record: RecordEpochPublication,
    bytes: Bytes,
}

impl CommunityService {
    pub(super) async fn maintain_account_record(&mut self) -> Result<()> {
        let Some(runtime) = self.accounts.clone() else {
            return Ok(());
        };
        crate::service::with_live_clock(async {
            let mut now = runtime.observe()?;
            let policy = self.facade.policy().lock().await;
            now = runtime.observe()?.max(now);
            let period = policy
                .record_epoch_settings(&runtime.period_key, now)
                .await
                .map_err(Error::Unavailable.redact())?;
            now = runtime.observe()?.max(now);
            let epoch = policy
                .epoch(now)
                .await
                .map_err(Error::Unavailable.redact())?;
            now = runtime.observe()?.max(now);
            let balance = policy.balance_publication(now).await;
            now = runtime.observe()?.max(now);
            // An envelope can expire before its record descriptor. Recovery
            // uses the SAME worker; this is never an accepting absence result.
            let current_balance = match balance {
                Ok(Some(balance)) => policy
                    .key_ring()
                    .ok()
                    .and_then(|ring| {
                        ring.verify(&balance, csgn::Kind::SettingsSnapshot, now)
                            .ok()
                            .and_then(|signed| {
                                serde_json::from_slice::<cblc::publication::PublicVerifierMaterial>(
                                    signed.payload(),
                                )
                                .ok()
                            })
                    })
                    .filter(|material| material.validate_at(&self.config.community, now).is_ok()),
                _ => None,
            };
            let due = self.account_record.as_ref().is_none_or(|cached| {
                let descriptor = cached.record.descriptor();
                current_balance
                    .as_ref()
                    .is_none_or(|material| material.record_epoch.as_ref() != Some(descriptor))
                    || descriptor.check_time(now).is_err()
                    || descriptor.policy_epoch != epoch
                    || descriptor.expires_at.checked_sub(descriptor.starts_at)
                        != Some(period.period_seconds)
            });
            drop(policy);
            if !due {
                return Ok(());
            }
            // The same owner recovers exact stored bytes after a retry/restart.
            // All failures remain uncertain/unavailable; an empty frontier is
            // never silently projected to a successfully published empty epoch.
            let publication = self
                .facade
                .publish_account_record(&runtime.period_key, || runtime.native_time())
                .await
                .map_err(|error| match error {
                    cmty::Error::Reconcile => Error::Reconcile,
                    _ => Error::Unavailable,
                })?;
            let result = async {
                runtime.observe()?;
                let descriptor = publication.record.descriptor();
                let object = publication.record.common_object();
                if descriptor.download_bytes > czkp::record::MAX_DOWNLOAD_BYTES
                    || descriptor.download_bytes != object.len() as u64
                {
                    return Err(Error::Unavailable);
                }
                // Verify the original owner relation before the one RAM copy.
                descriptor
                    .check_object(object)
                    .map_err(Error::Unavailable.redact())?;
                let record = PublishedRecord {
                    bytes: Bytes::copy_from_slice(object),
                    record: publication.record,
                };
                runtime.observe()?;
                // Refresh through the actual Policy, never a host-made Feed.
                self.refresh(runtime.observe()?).await?;
                runtime.observe()?;
                self.account_record = Some(record);
                self.current_account_record().await?;
                Ok(())
            }
            .await;
            // Native publication may already be durable on every tail failure.
            result.map_err(|_| Error::Reconcile)
        })
        .await
    }

    pub(crate) async fn current_account_record(&self) -> Result<Bytes> {
        let runtime = self.accounts.as_ref().ok_or(Error::Unavailable)?;
        let cached = self.account_record.as_ref().ok_or(Error::Unavailable)?;
        crate::service::with_live_clock(async {
            let mut now = runtime.observe()?;
            let policy = self.facade.policy().lock().await;
            now = runtime.observe()?.max(now);
            let balance = policy
                .balance_publication(now)
                .await
                .map_err(Error::Unavailable.redact())?
                .ok_or(Error::Unavailable)?;
            now = runtime.observe()?.max(now);
            let signed = policy
                .key_ring()
                .map_err(Error::Unavailable.redact())?
                .verify(&balance, csgn::Kind::SettingsSnapshot, now)
                .map_err(Error::Unavailable.redact())?;
            let material: cblc::publication::PublicVerifierMaterial =
                serde_json::from_slice(signed.payload()).map_err(Error::Unavailable.redact())?;
            material
                .validate_at(&self.config.community, now)
                .map_err(Error::Unavailable.redact())?;
            if material.record_epoch.as_ref() != Some(cached.record.descriptor()) {
                return Err(Error::Unavailable);
            }
            let period = policy
                .record_epoch_settings(&runtime.period_key, now)
                .await
                .map_err(Error::Unavailable.redact())?;
            now = runtime.observe()?.max(now);
            cached
                .record
                .descriptor()
                .validate(&cached.record.descriptor().community, period.period_seconds)
                .map_err(Error::Unavailable.redact())?;
            cached
                .record
                .descriptor()
                .check_time(now)
                .map_err(Error::Unavailable.redact())?;
            if now >= signed.valid_until() || now >= material.policy.account.policy_valid_until {
                return Err(Error::Unavailable);
            }
            // Carry the actual signed/epoch deadline into the outer HTTP/JSON
            // final clock cut, including a clock that blocks after this return.
            crate::service::publication::expires_at(
                signed
                    .valid_until()
                    .min(material.policy.account.policy_valid_until)
                    .min(cached.record.descriptor().expires_at),
            )?;
            now = runtime.observe()?;
            cached
                .record
                .descriptor()
                .check_time(now)
                .map_err(Error::Unavailable.redact())?;
            if now >= signed.valid_until() || now >= material.policy.account.policy_valid_until {
                return Err(Error::Unavailable);
            }
            Ok(cached.bytes.clone())
        })
        .await
    }
}
