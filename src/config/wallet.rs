//! Explicit isolated wallet signer and original publication configuration.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletConfig {
    /// Separate literal-wallet csgn seed, never the passport signing seed.
    pub signing_seed_file: String,
    /// Original cgbl WalletPublicationConfig JSON, supplied by the host.
    pub publication_file: String,
    /// Explicit maximum wallet signing lifetime, independent of passports.
    pub signer_max_seconds: u64,
    /// The wallet's confirmation-stamp issuer key (cpsd secret encoding, cohort included),
    /// never the passport key. Absent: the wallet issues no stamps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp_key_file: Option<String>,
    /// Stamps per member and window (rulebook setting; default 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp_limit: Option<u32>,
    /// Stamp budget window in seconds (default one day).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp_period_seconds: Option<u64>,
    /// How long the same stamp request is answered again with the same stamp (default ten
    /// minutes; 0 disables it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp_replay_seconds: Option<u64>,
}
