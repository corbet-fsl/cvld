//! Original source-authenticated blind root credential exchange.
use super::*;

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RootBoardIssueChallenge {
    pub challenge: String,
    pub signed_context: Vec<u8>,
    pub signed_source_request: Vec<u8>,
    /// Exclusive retained nonce/session expiry.
    pub expires: u64,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RootBoardIssueFinish {
    pub challenge: String,
    /// Original bounded CPSD same-holder issuance proof.
    pub proof: Vec<u8>,
}
