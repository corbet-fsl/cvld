//! Original target-Policy entitlement, never admission or a role assertion.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreationRecipientRequest {
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
