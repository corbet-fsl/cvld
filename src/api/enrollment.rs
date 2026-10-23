use super::PresentationInput;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The original first-registration ceremony and its retained server deadline.
/// These public lifecycle fields do not authorize completion or extend its life.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InitialCeremony {
    pub ceremony: String,
    pub user: String,
    #[schema(value_type = std::collections::BTreeMap<String, serde_json::Value>, additional_properties = true)]
    pub options: serde_json::Value,
    pub checked_at: u64,
    pub expires_at: u64,
}

/// Public original creation reference, bound only after genuine registration.
/// It is not a passkey root, holder seed, recovery key or authority capability.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InitialRegistrationBegin {
    pub passport: PresentationInput,
    pub seed: [u8; 32],
}

/// Bind the original publication to this session's initial registration.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InitialPublicationBind {
    pub seed: [u8; 32],
    pub publication: [u8; 32],
    /// Genesis stamp evidence of the member's first lineage (`cchr::genesis_stamp`
    /// encoding): required iff the session is a device-key session, refused otherwise.
    /// Its stamp digest is recorded once; an equal retry of a bound publication is not
    /// re-verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<u8>>,
}

/// Own enrollment provenance only; grants no root creation, signing or use.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InitialCreationResponse {
    pub seed: [u8; 32],
    pub publication: Option<[u8; 32]>,
    pub checked_at: u64,
}

/// Continue the retained wallet ceremony after its genuine UUID is known.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GlobalInitialRegistrationContinue {
    pub ceremony: String,
    pub seed: [u8; 32],
}
