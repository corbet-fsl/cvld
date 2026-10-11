//! Explicit capacity limits; enrollment identity comes from the native owner.
use crate::error::{Error, Result};
use cblc::enrollment::{EnrollmentConfig, EnrollmentService};
use serde::{Deserialize, Serialize};

pub(crate) type Enrollment = EnrollmentService<Box<dyn Fn() -> u64 + Send>>;

/// Caller-selected registry limits. Scope, signer, admission digest and period
/// are inherited from the same configured native accounting owner.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentLimits {
    pub max_members: u32,
    pub max_retained_slots: u32,
    pub max_publication_bytes: u64,
}

impl EnrollmentLimits {
    pub(crate) fn configuration(
        &self,
        community: &str,
        admission_digest: &str,
        operator: [u8; 32],
        period: u64,
    ) -> Result<EnrollmentConfig> {
        let config = EnrollmentConfig {
            community_id: community.into(),
            policy_digest: admission_digest.into(),
            operator_public_key: operator,
            checkpoint_period_seconds: period,
            max_members: self.max_members,
            max_retained_slots: self.max_retained_slots,
            max_publication_bytes: self.max_publication_bytes,
        };
        config.validate().map_err(Error::Invalid.redact())?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests;
