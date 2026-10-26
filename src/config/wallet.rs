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
    /// How long the same stamp request is answered again with the same stamp (default ten
    /// minutes; 0 disables it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp_replay_seconds: Option<u64>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn removed_stamp_budget_settings_are_refused_as_unknown_keys() {
        let base = json!({
            "signing_seed_file": "seed",
            "publication_file": "publication",
            "signer_max_seconds": 8640000,
        });
        assert!(serde_json::from_value::<super::WalletConfig>(base.clone()).is_ok());
        for field in ["stamp_limit", "stamp_period_seconds"] {
            let mut value = base.clone();
            value[field] = json!(20);
            assert!(
                serde_json::from_value::<super::WalletConfig>(value).is_err(),
                "{field}"
            );
        }
    }
}
