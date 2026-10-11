//! Explicit daily host inputs; no member or anonymous request chooses authority.
use super::config::bounded;
use crate::error::{Error, Result};
use cblc::{
    accounting_ledger::AdmissionKeyReconciliation,
    settlement::{SettlementCapability, SettlementConfig, SettlementIssuer},
};
use serde::{Deserialize, Serialize};
use std::io::Read;

/// Original provisioned outcome issuer and explicit operational limits.
/// Files contain the original public descriptors and PKCS#1 private key. The
/// private bytes are wiped during construction and never enter a worker DTO.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementFiles {
    pub quota_key: String,
    pub epoch_file: String,
    pub private_key_file: String,
    pub room_epochs_file: String,
    pub incarnation: String,
    pub pending_capacity: u32,
    pub issuance_members_capacity: u32,
}

pub(crate) struct Owners {
    pub(crate) admission: AdmissionKeyReconciliation,
    pub(crate) settlement: Target,
}

pub(crate) struct Target {
    pub(crate) policy_epoch: u64,
    pub(crate) period_seconds: u64,
    pub(crate) quota: u16,
}
pub(crate) struct Prepared {
    pub(crate) config: SettlementConfig,
    pub(crate) issuer: SettlementIssuer,
    pub(crate) quota_key: String,
    pub(crate) incarnation: String,
}

impl SettlementFiles {
    pub(crate) fn prepare(&self, community: &str, target: Target) -> Result<Prepared> {
        if self.quota_key.trim().is_empty()
            || self.quota_key.len() > 256
            || self.quota_key.contains('\0')
            || self.incarnation.is_empty()
            || self.incarnation.len() > 256
            || target.period_seconds != 86_400
            || self.pending_capacity == 0
            || self.pending_capacity > 1 << 20
            || self.issuance_members_capacity == 0
            || self.issuance_members_capacity > 1 << 20
        {
            return Err(Error::Invalid);
        }
        let config = SettlementConfig {
            epoch: serde_json::from_slice(&bounded(&self.epoch_file, 65_536)?)
                .map_err(Error::Invalid.redact())?,
            policy_epoch: target.policy_epoch,
            period_seconds: target.period_seconds,
            quota: target.quota,
            pending_capacity: self.pending_capacity,
            issuance_members_capacity: self.issuance_members_capacity,
            // The original owner permits 64 RSA-3072 descriptors. Include the
            // JSON byte-array expansion instead of truncating valid inventory.
            room_epochs: serde_json::from_slice(&bounded(&self.room_epochs_file, 256 * 1024)?)
                .map_err(Error::Invalid.redact())?,
        };
        SettlementCapability {
            epoch: config.epoch.clone(),
            policy_epoch: config.policy_epoch,
            period_seconds: config.period_seconds,
            quota: config.quota,
        }
        .validate(community, target.policy_epoch)
        .map_err(Error::Invalid.redact())?;
        if config.room_epochs.len() > 64
            || config.room_epochs.iter().any(|room| {
                room.community != community
                    || room.context().is_err()
                    || room.public_key_der == config.epoch.public_key_der
            })
        {
            return Err(Error::Invalid);
        }
        let file =
            std::fs::File::open(&self.private_key_file).map_err(Error::Unavailable.redact())?;
        // One fixed allocation also wipes partial reads and the overflow
        // sentinel. No reallocating buffer can leave freed DER bytes behind.
        let mut private = zeroize::Zeroizing::new(vec![0; 16_385]);
        let mut file = file.take(16_385);
        let mut used = 0;
        while used < private.len() {
            let read = file
                .read(&mut private[used..])
                .map_err(Error::Unavailable.redact())?;
            if read == 0 {
                break;
            }
            used += read;
        }
        if used > 16_384 {
            return Err(Error::Invalid);
        }
        private.truncate(used);
        let issuer = SettlementIssuer::from_pkcs1_der(config.epoch.clone(), &private)
            .map_err(Error::Invalid.redact())?;
        // Prepared retains only the original wiping private-key owner. Raw DER
        // is destroyed before native construction hands anything to async code.
        Ok(Prepared {
            config,
            issuer,
            quota_key: self.quota_key.clone(),
            incarnation: self.incarnation.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
