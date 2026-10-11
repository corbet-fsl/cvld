//! Original target-Policy entitlement, never admission or a role assertion.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What the prepared recipient may later receive; fixed at preparation and
/// never reinterpreted by the Global Root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CreationPurpose {
    /// The first Root of the community being created.
    Root,
    /// A distinct founder who joins as Admin; never an existing member.
    Founder,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreationRecipientRequest {
    pub purpose: CreationPurpose,
    /// Retain the original opaque ID for a retry; omitted only on first prepare.
    pub id: Option<String>,
    /// Explicit original exclusive entitlement deadline, never extended on retry.
    pub expires_at: u64,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreationRecipient {
    pub recipient: String,
    pub id: String,
    pub expires_at: u64,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CommunityCreationRequest {
    /// A target explicitly linked by the trusted hosting caller.
    pub community: String,
    /// Opaque target-owned reference; no target bearer or member UUID crosses.
    pub recipient: String,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CommunityCreationInvitation {
    pub invitation: Vec<u8>,
    pub id: String,
    pub expires_at: u64,
    pub checked_at: u64,
}
