mod root_board;
mod wallet;
pub use root_board::RootCommunityConfig;
pub use wallet::WalletConfig;

use crate::error::{Error, Result};
use cmty::cplc::crbk;
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
    /// Rulebook stamp cohort in seconds (default one UTC day); stamps of any other cohort are
    /// refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp_cohort_seconds: Option<u64>,
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
    /// The creator's choices, applied once to the founding rulebook of a community
    /// created through the hub. Absent for deployed (static) communities.
    #[serde(default)]
    pub creation: Option<CreationPlan>,
    /// The database holds several communities, each in its own scope (set by the
    /// hub's factory); the service record is then kept per community.
    #[serde(default)]
    pub shared_database: bool,
}

/// Display name and admission gates chosen at creation. They are written into the
/// founding rulebook as community-layer values, so the community never exists
/// without them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreationPlan {
    pub display_name: String,
    pub gates: Vec<String>,
}

impl CreationPlan {
    /// Largest display name, in characters.
    pub const NAME_CHARS: usize = 64;
    /// The gate every community has; it is enforced by the legal veto itself.
    pub const LEGAL: &'static str = "legal";

    /// Syntax check of what a creator sent.
    pub fn validate(&self) -> Result<()> {
        let name = self.display_name.trim();
        if name.is_empty()
            || name != self.display_name
            || name.chars().count() > Self::NAME_CHARS
            || name.chars().any(char::is_control)
            || self.gates.len() > 16
            || !self.gates.iter().any(|gate| gate == Self::LEGAL)
        {
            return Err(Error::Invalid);
        }
        for (index, gate) in self.gates.iter().enumerate() {
            let valid = !gate.is_empty()
                && gate.len() <= 32
                && gate
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
            if !valid || self.gates[..index].contains(gate) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }

    /// Write the plan into the founding rulebook: the admission policy keeps the
    /// template's global requirements and only the community requirements the
    /// creator chose (`voucher` stands for the `cvch` gate), and the display name
    /// becomes a community setting. A gate the template does not offer is refused.
    pub fn apply(&self, rulebook: &mut crbk::Rulebook) -> Result<()> {
        self.validate()?;
        let key = crbk::action_key(cmty::ADMISSION_ACTION);
        let default = rulebook
            .catalog()
            .get(&key)
            .ok_or(Error::Invalid)?
            .default
            .clone();
        let mut policy: crbk::ActionPolicy =
            serde_json::from_value(default).map_err(Error::Invalid.redact())?;
        fn name_of(gate: &str) -> &str {
            if gate == "voucher" { "cvch" } else { gate }
        }
        for gate in &self.gates {
            if gate != Self::LEGAL
                && !policy
                    .all_of
                    .iter()
                    .any(|requirement| requirement.gate == name_of(gate))
            {
                return Err(Error::Invalid);
            }
        }
        policy.all_of.retain(|requirement| {
            requirement.level == crbk::GateLevel::Global
                || self
                    .gates
                    .iter()
                    .any(|gate| name_of(gate) == requirement.gate)
        });
        rulebook
            .set_community(
                &key,
                Some(serde_json::to_value(policy).map_err(Error::Invalid.redact())?),
            )
            .map_err(Error::Invalid.redact())?;
        if !rulebook.catalog().contains_key(DISPLAY_NAME) {
            rulebook
                .define(
                    DISPLAY_NAME,
                    crbk::Setting {
                        value_type: crbk::SettingType::String,
                        nullable: false,
                        default: serde_json::json!(""),
                        bounds: crbk::Bounds::default(),
                        lowest_layer: crbk::Layer::Community,
                        kind: crbk::SettingKind::Technical,
                    },
                )
                .map_err(Error::Invalid.redact())?;
        }
        rulebook
            .set_community(DISPLAY_NAME, Some(serde_json::json!(self.display_name)))
            .map_err(Error::Invalid.redact())
    }
}

/// Community-layer setting that holds the name members see.
pub const DISPLAY_NAME: &str = "community.display_name";
impl CommunityConfig {
    pub fn shutdown_budget(&self) -> Result<Duration> {
        shutdown_budget(self.shutdown_seconds)
    }

    pub fn read(path: &str) -> Result<Self> {
        serde_json::from_slice(&std::fs::read(path).map_err(Error::Unavailable.redact())?)
            .map_err(Error::Invalid.redact())
    }
}
