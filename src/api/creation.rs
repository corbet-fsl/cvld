//! Self-service community creation: blind token issuance, creation, and the
//! creator's claim of the first admin seat.
use crate::creation_token::Token;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Ask for one creation token: the client sends a blinded random message.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreationTokenRequest {
    pub blinded: Vec<u8>,
}
/// The issuer's blind signature; the client unblinds it locally.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreationTokenResponse {
    pub blind_signature: Vec<u8>,
}
/// The public key that verifies creation tokens, DER encoded.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreationTokenKey {
    pub public_key: Vec<u8>,
}
/// A finished creation token as the wire shape of `creation_token::Token`.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreationTokenWire {
    pub message: Vec<u8>,
    pub randomizer: Vec<u8>,
    pub signature: Vec<u8>,
}
impl From<CreationTokenWire> for Token {
    fn from(value: CreationTokenWire) -> Self {
        Self {
            message: value.message,
            randomizer: value.randomizer,
            signature: value.signature,
        }
    }
}
/// Start a new community. No session: the token alone proves capacity, so the
/// platform cannot link the creator to the community.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CommunityCreate {
    /// Permanent address, `^[a-z0-9]{8,30}$`, not reserved or taken.
    pub address: String,
    pub token: CreationTokenWire,
    /// Name members see; 1 to 64 characters, no control characters.
    pub display_name: String,
    /// Admission gates the creator chose. `legal` is required; `voucher` is the
    /// community voucher gate; any other must be offered by the platform template.
    pub gates: Vec<String>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CommunityCreated {
    /// Opaque community id (32 hex characters).
    pub id: String,
    /// SHA-256 of the community's founding key document (64 hex characters).
    pub fingerprint: String,
    pub community_host: String,
    pub vault_host: String,
    /// Bearer secret that lets the creator claim the first admin seat.
    pub claim: Vec<u8>,
    /// The shell is discarded unclaimed after this time (unix seconds).
    pub expires_at: u64,
}
/// The creator, after registering in the new community, claims the first seat.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreationClaim {
    pub claim: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreationClaimed {
    /// Creation id to present as `creation` in `credential_issue`.
    pub id: String,
    pub expires_at: u64,
}

/// Why Root ends a community.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    Legal,
    Terms,
    Name,
}
impl TerminationReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::Legal => "legal",
            Self::Terms => "terms",
            Self::Name => "name",
        }
    }
}
/// Root ends a community at once: nothing is served, hostnames go, data is
/// deleted (or, under a legal hold, retained until the hold ends).
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CommunityTerminate {
    pub address: String,
    pub reason: TerminationReason,
    /// Legal orders only: keep the data, root-only, until this unix time.
    #[serde(default)]
    pub hold_until: Option<u64>,
    /// Also block the address from ever being created again.
    #[serde(default)]
    pub block_name: bool,
}
