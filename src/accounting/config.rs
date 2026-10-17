//! Explicit operator-owned economic policy, native artifacts and execution caps.
use super::{
    build::Cancellation,
    clock::AccountRuntime,
    enrollment::{Enrollment, EnrollmentLimits},
    settlement::{Owners, Prepared, SettlementFiles},
    storage::Store,
};
use crate::{
    config::Config,
    error::{Error, Result},
    service::Clock,
};
use cblc::{
    accounting::AccountStatement,
    accounting_ledger::{AccountLedger, AccountLedgerPolicy, startup_clock_floor},
    accounting_service::{AccountService, NativeAccountVerifier},
    admission::AdmissionTrust,
    artifacts::{AccountArtifacts, ArtifactBytes, ExtensionArtifacts, NativeVerifierOptions},
    extensions::{ExtensionActivation, ExtensionPolicy},
    verification::{ExtensionLimits, NativeExtensionVerifier},
};
use serde::{Deserialize, Serialize};
use std::{io::Read, num::NonZeroUsize, path::PathBuf, sync::Arc, time::Duration};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// Key in the actual authenticated Rulebook; no period is inferred.
    pub period_key: String,
    pub ledger_policy_file: String,
    pub extension_policy_file: String,
    /// Immutable admission trust, distinct from a tunable economic digest.
    pub admission_policy_digest: String,
    pub operator_seed_file: String,
    pub certificate_seed_file: String,
    /// Whose certificate issuer key signs this community's certificates: the
    /// platform's (`certificate_seed_file` of the template, the default) or one
    /// derived for each community incarnation. The ledger records the key in its
    /// issuer key ring, so changing the seed is a rotation, never a new artifact.
    #[serde(default, skip_serializing_if = "CertificateKeyScope::is_platform")]
    pub certificate_key_scope: CertificateKeyScope,
    pub account_artifacts: ArtifactFiles,
    pub extension_artifacts: ArtifactFiles,
    pub activation_statement_file: String,
    pub activation_proof_file: String,
    pub account_execution: NativeExecution,
    pub update_execution: NativeExecution,
    pub anonymous_execution: NativeExecution,
    pub extension_limits: VerificationLimits,
    pub enrollment: EnrollmentLimits,
    /// Mandatory daily settlement configuration; there is no native legacy
    /// early-application route or inferred quota for the configured product.
    pub settlement: SettlementFiles,
    pub max_request_bytes: usize,
    /// Set only in the hub's template: an absolute directory that holds the inputs
    /// derived for each created community (seeds, daily settlement key, policy
    /// window, activation). The per-community files named above are then ignored
    /// and replaced; the platform-wide artifacts, limits and execution stay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenants_dir: Option<String>,
}

/// See [`AccountConfig::certificate_key_scope`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateKeyScope {
    #[default]
    Platform,
    Community,
}
impl CertificateKeyScope {
    fn is_platform(&self) -> bool {
        *self == Self::Platform
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFiles {
    pub manifest_file: String,
    /// Independently configured pin, never taken from the downloaded manifest.
    pub manifest_sha256: [u8; 32],
    pub circuit_file: String,
    pub keys_file: String,
    pub srs_g1_file: String,
    pub srs_g2_file: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExecution {
    pub executable: String,
    pub timeout_ms: u64,
    pub maximum_parallel: usize,
    pub max_proof_bytes: usize,
    pub threads: usize,
    pub memory_megabytes: usize,
}
impl NativeExecution {
    fn options(&self) -> Result<NativeVerifierOptions> {
        let executable = PathBuf::from(&self.executable);
        let timeout = Duration::from_millis(self.timeout_ms);
        if !executable.is_absolute()
            || self.timeout_ms == 0
            || std::time::Instant::now().checked_add(timeout).is_none()
            || self.maximum_parallel == 0
            || self.max_proof_bytes == 0
            || self.max_proof_bytes > 4 * 1024 * 1024
            || self.threads == 0
            || self.memory_megabytes == 0
        {
            return Err(Error::Invalid);
        }
        Ok(NativeVerifierOptions {
            executable,
            timeout,
            maximum_parallel: self.maximum_parallel,
            max_proof_bytes: self.max_proof_bytes,
            threads: self.threads,
            memory_megabytes: self.memory_megabytes,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationLimits {
    pub global_burst: u32,
    pub subject_burst: u32,
    pub replenish_ms: u64,
    pub maximum_keys: usize,
}
impl VerificationLimits {
    fn limits(&self) -> Result<ExtensionLimits> {
        if self.global_burst == 0 || self.subject_burst == 0 || self.replenish_ms == 0 {
            return Err(Error::Invalid);
        }
        Ok(ExtensionLimits {
            global_burst: self.global_burst,
            subject_burst: self.subject_burst,
            replenish: Duration::from_millis(self.replenish_ms),
            maximum_keys: NonZeroUsize::new(self.maximum_keys).ok_or(Error::Invalid)?,
        })
    }
}

struct PublicArtifacts {
    manifest: Vec<u8>,
    circuit: Vec<u8>,
    keys: Vec<u8>,
    g1: Vec<u8>,
    g2: Vec<u8>,
    pin: [u8; 32],
}
impl ArtifactFiles {
    fn read(&self) -> Result<PublicArtifacts> {
        if self.manifest_sha256 == [0; 32] {
            return Err(Error::Invalid);
        }
        Ok(PublicArtifacts {
            manifest: bounded(&self.manifest_file, 65536)?,
            circuit: bounded(&self.circuit_file, 64 * 1024 * 1024)?,
            keys: bounded(&self.keys_file, 1024 * 1024)?,
            g1: bounded(&self.srs_g1_file, 128 * 1024 * 1024)?,
            g2: bounded(&self.srs_g2_file, 128)?,
            pin: self.manifest_sha256,
        })
    }
}
impl PublicArtifacts {
    fn bytes(&self) -> ArtifactBytes<'_> {
        ArtifactBytes {
            manifest: &self.manifest,
            manifest_sha256: self.pin,
            circuit: &self.circuit,
            keys: &self.keys,
            srs_g1: &self.g1,
            srs_g2: &self.g2,
        }
    }
}
pub(super) fn bounded(path: &str, maximum: usize) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).map_err(Error::Unavailable.redact())?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(Error::Unavailable.redact())?;
    if bytes.len() > maximum {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

pub(crate) type Service = AccountService<NativeAccountVerifier, Box<dyn Fn() -> u64 + Send>>;

impl AccountConfig {
    /// Call once on an ordinary native owner thread. No service request can
    /// select files, a signer, clock, period, asset or verifier configuration.
    pub(crate) fn build(
        &self,
        db: &crlt::Db,
        community: &str,
        identity: [u8; 32],
        owners: Owners,
        clock: Arc<dyn Clock>,
        runtime: tokio::runtime::Handle,
        cancellation: &Cancellation,
    ) -> Result<(Service, Enrollment, Arc<AccountRuntime>, Prepared)> {
        let Owners {
            admission: keys,
            settlement: target,
        } = owners;
        if self.period_key.is_empty()
            || self.period_key.len() > 256
            || self.max_request_bytes == 0
            || self.max_request_bytes > 16 * 1024 * 1024
            || keys.target.policy_keys.issuer() != community
        {
            return Err(Error::Invalid);
        }
        cancellation.check()?;
        let settlement = self.settlement.prepare(community, target)?;
        let mut store =
            Store::new(db, community, runtime.clone()).map_err(Error::Unavailable.redact())?;
        let durable_floor = startup_clock_floor(&mut store).map_err(Error::Unavailable.redact())?;
        let observed = Arc::new(AccountRuntime::new(
            clock,
            durable_floor,
            self.max_request_bytes,
            self.period_key.clone(),
        )?);
        let fenced = observed.clone();
        cancellation.register(move || fenced.fence());
        cancellation.check()?;
        let policy: AccountLedgerPolicy =
            serde_json::from_slice(&bounded(&self.ledger_policy_file, 1024 * 1024)?)
                .map_err(Error::Invalid.redact())?;
        let extension: ExtensionPolicy =
            serde_json::from_slice(&bounded(&self.extension_policy_file, 1024 * 1024)?)
                .map_err(Error::Invalid.redact())?;
        let account = self.account_artifacts.read()?;
        let verifier = NativeAccountVerifier::new(
            self.account_execution.options()?,
            AccountArtifacts::authenticate(account.bytes()).map_err(Error::Invalid.redact())?,
        )
        .map_err(Error::Invalid.redact())?;
        let account_cancel = verifier.cancellation();
        cancellation.register(move || account_cancel.cancel());
        let extensions = self.extension_artifacts.read()?;
        let extensions = NativeExtensionVerifier::new(
            self.update_execution.options()?,
            self.anonymous_execution.options()?,
            ExtensionArtifacts::authenticate(extensions.bytes())
                .map_err(Error::Invalid.redact())?,
        )
        .map_err(Error::Invalid.redact())?;
        let extension_cancel = extensions.cancellation();
        cancellation.register(move || extension_cancel.cancel());
        cancellation.check()?;
        cblc::extensions::ExtensionVerifier::require_record_epoch(&extensions)
            .map_err(Error::Invalid.redact())?;
        let statement: AccountStatement =
            serde_json::from_slice(&bounded(&self.activation_statement_file, 1024 * 1024)?)
                .map_err(Error::Invalid.redact())?;
        let proof = bounded(
            &self.activation_proof_file,
            self.update_execution.max_proof_bytes,
        )?;
        let operator = zeroize::Zeroizing::new(Config::seed(&self.operator_seed_file)?);
        // Both original owners use the same configured operator and checkpoint
        // period, the same scoped database, and the same sticky live observer.
        // Registry construction performs no enrollment or root installation.
        let enrollment_operator = ed25519_dalek_v2::SigningKey::from_bytes(&operator);
        let enrollment_config = self.enrollment.configuration(
            community,
            &self.admission_policy_digest,
            enrollment_operator.verifying_key().to_bytes(),
            policy.checkpoint_period_seconds,
        )?;
        let enrollment_store = cblc::enrollment::EnrollmentStore::new(
            Store::new(db, community, runtime).map_err(Error::Unavailable.redact())?,
            enrollment_config,
        )
        .map_err(Error::Invalid.redact())?;
        let enrollment_clock = observed.clone();
        let enrollment_clock: Box<dyn Fn() -> u64 + Send> =
            Box::new(move || enrollment_clock.native_time());
        let enrollment = cblc::enrollment::EnrollmentService::new(
            enrollment_store,
            enrollment_operator,
            enrollment_clock,
        )
        .map_err(Error::Invalid.redact())?;
        let certificate = zeroize::Zeroizing::new(Config::seed(&self.certificate_seed_file)?);
        let certificate = cssr::certificate::CertificateIssuer::new(&certificate)
            .map_err(Error::Invalid.redact())?;
        let policy_keys = keys.target.policy_keys.clone();
        let ledger = AccountLedger::with_store_reconciled_admission_keys(
            store,
            AdmissionTrust {
                community_id: community.into(),
                policy_digest: self.admission_policy_digest.clone(),
                policy_keys,
            },
            policy,
            verifier,
            ed25519_dalek_v2::SigningKey::from_bytes(&operator),
            keys,
            || observed.native_time(),
        )
        .map_err(Error::Invalid.redact())?
        .with_extensions(
            extension,
            extensions,
            self.extension_limits.limits()?,
            ExtensionActivation {
                account: statement,
                proof,
            },
        )
        .map_err(Error::Invalid.redact())?;
        cancellation.check()?;
        observed.observe()?;
        let native_clock = observed.clone();
        let clock: Box<dyn Fn() -> u64 + Send> = Box::new(move || native_clock.native_time());
        // The configured issuer becomes the open period of the ledger's issuer key
        // ring (a new seed retires the previous key, never removes it); its
        // certificates bind the community identity, not the reusable address.
        AccountService::new(ledger, clock, self.max_request_bytes)
            .and_then(|service| service.with_extension_issuer(certificate, identity))
            .map(|service| (service, enrollment, observed, settlement))
            .map_err(Error::Invalid.redact())
    }
}
