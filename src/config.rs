mod root_board;
mod wallet;
pub use root_board::RootCommunityConfig;
pub use wallet::WalletConfig;

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Supplied explicitly; loading never searches for credentials.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub domain: String,
    pub database_url: String,
    pub database_token_file: Option<String>,
    pub signing_seed_file: String,
    pub issuer_key_file: String,
    pub uniqueness_key_file: String,
    pub policy_file: String,
    pub policy_authority_file: String,
    /// Existing operator's opaque account UUID; first enrolment uses bootstrap.
    pub root_user: String,
    pub root_bootstrap_file: Option<String>,
    /// Required total budget from shutdown signal through HTTP and runtime drain.
    pub shutdown_seconds: u64,
    pub session_seconds: u64,
    pub pending_capacity: usize,
    pub throttle_burst: u32,
    pub throttle_interval_ms: u64,
    /// Peers (addresses or CIDR ranges) whose `cf-connecting-ip` is believed, in
    /// addition to loopback: the tunnel. Invalid entries refuse to start.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Oblivious HTTP gateway; absent means the door is reachable directly only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ohttp: Option<OhttpConfig>,
    pub publication_seconds: u64,
    pub signer_max_seconds: u64,
    pub development: bool,
    /// Providers are enabled only through explicit contact configuration.
    #[serde(default)]
    pub contacts: Option<crate::contact_gates::ContactConfig>,
    /// Unconfigured wallet certificate/trust authority is unavailable.
    #[serde(default)]
    pub wallet: Option<WalletConfig>,
}
fn shutdown_budget(seconds: u64) -> Result<Duration> {
    let duration = Duration::from_secs(seconds);
    if seconds == 0 || Instant::now().checked_add(duration).is_none() {
        return Err(Error::Invalid);
    }
    Ok(duration)
}
impl Config {
    pub fn shutdown_budget(&self) -> Result<Duration> {
        shutdown_budget(self.shutdown_seconds)
    }

    pub fn read(path: &str) -> Result<Self> {
        serde_json::from_slice(&std::fs::read(path).map_err(Error::Unavailable.redact())?)
            .map_err(Error::Invalid.redact())
    }
    pub fn secret(path: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        std::fs::read(path)
            .map(zeroize::Zeroizing::new)
            .map_err(Error::Unavailable.redact())
    }
    pub fn seed(path: &str) -> Result<[u8; 32]> {
        Self::secret(path)?
            .as_slice()
            .try_into()
            .map_err(Error::Invalid.redact())
    }
}

/// Oblivious HTTP gateway settings. Key material is read from files and never
/// appears in this document.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OhttpConfig {
    /// The exact door host whose requests arrive through the gateway.
    pub authority: String,
    pub keys: Vec<OhttpKeyFile>,
    /// Optional file with the secret a front proxy sends in `x-relay-auth`.
    #[serde(default)]
    pub relay_secret_file: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OhttpKeyFile {
    pub key_id: u8,
    /// Raw secret input keying material (32 bytes or more).
    pub ikm_file: String,
    /// Unix seconds after which the key no longer decrypts.
    pub not_after: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    pub user: String,
    pub bootstrap_file: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommunityConfig {
    pub listen: String,
    pub domain: String,
    pub community: String,
    pub database_url: String,
    pub database_token_file: Option<String>,
    pub signing_seed_file: String,
    /// Derived founding seed of a community created at runtime. Never read from
    /// or written to a document; when set it replaces `signing_seed_file`.
    #[serde(skip)]
    pub founding_seed: Option<zeroize::Zeroizing<[u8; 32]>>,
    pub rulebook_file: String,
    pub schema_file: String,
    pub global_key_ring_file: String,
    /// Authenticated public global status, refreshed by the operator.
    pub global_status_file: String,
    pub minimum_global_epoch: u64,
    pub minimum_global_revision: u64,
    pub global_gates: Vec<String>,
    pub root: Operator,
    pub admin: Operator,
    pub pending_days: u32,
    pub lease_months: u32,
    /// Required total budget from shutdown signal through HTTP and runtime drain.
    pub shutdown_seconds: u64,
    pub session_seconds: u64,
    pub pending_capacity: usize,
    pub throttle_burst: u32,
    pub throttle_interval_ms: u64,
    /// Peers (addresses or CIDR ranges) whose `cf-connecting-ip` is believed, in
    /// addition to loopback: the tunnel. Invalid entries refuse to start.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Oblivious HTTP gateway; absent means the door is reachable directly only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ohttp: Option<OhttpConfig>,
    pub publication_seconds: u64,
    pub signer_max_seconds: u64,
    pub minimum_notice_seconds: u64,
    pub voucher_provider: String,
    /// Paid access is off unless an exact account/offer is supplied explicitly.
    #[serde(default)]
    pub payments: Option<crate::payments::PaymentConfig>,
    /// Native accounts require an explicit economic policy, verifier and period.
    #[serde(default)]
    pub accounting: Option<crate::accounting::AccountConfig>,
}
impl CommunityConfig {
    pub fn shutdown_budget(&self) -> Result<Duration> {
        shutdown_budget(self.shutdown_seconds)
    }

    pub fn read(path: &str) -> Result<Self> {
        serde_json::from_slice(&std::fs::read(path).map_err(Error::Unavailable.redact())?)
            .map_err(Error::Invalid.redact())
    }
}
