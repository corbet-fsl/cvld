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
}
