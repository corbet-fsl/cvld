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
    /// The creator's device proved this community's accounting genesis (see
    /// `community_terms`). Required when the platform runs accounting; the hub
    /// verifies it and refuses a proof for another community or policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<AccountingActivation>,
}
/// Ask what a device must prove before it creates a community at this address.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CommunityTermsRequest {
    pub address: String,
}
/// Ask whether an address can be used, how long it feels, and for alternatives.
/// No session: it reveals nothing the public name space does not.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressCheck {
    /// The address the creator is typing (may be incomplete).
    pub address: String,
    /// The display name suggestions are derived from; empty for none.
    #[serde(default)]
    pub display_name: String,
    /// How many suggestions at most (0 to 8).
    #[serde(default)]
    pub suggestions: u8,
}
/// Why an address is refused, if it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddressRefusal {
    TooShort,
    TooLong,
    Charset,
    Reserved,
    Offensive,
    /// Syntactically fine but held by a live, ending or held community, or blocked.
    Taken,
}
/// Length hint for the creation form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddressLight {
    Red,
    Amber,
    Green,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressAnswer {
    pub available: bool,
    pub refusal: Option<AddressRefusal>,
    pub light: AddressLight,
    /// Valid and currently available addresses derived from the display name.
    pub suggestions: Vec<String>,
}
/// The public inputs of the accounting genesis proof; absent without accounting.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CommunityTerms {
    pub accounting: Option<AccountingTermsWire>,
}
/// The account policy window and extension policy the community will run with.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountingTermsWire {
    /// The standing and voucher values of the community's rulebook, by catalogue key.
    #[schema(value_type = Object)]
    pub standing: serde_json::Map<String, serde_json::Value>,
    /// The hub's clock when it named these terms (unix seconds).
    pub observed_at: u64,
    #[schema(value_type = Object)]
    pub ledger_policy: serde_json::Value,
    #[schema(value_type = Object)]
    pub extension_policy: serde_json::Value,
}
/// A creator device's genesis statement and proof for exactly this community.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountingActivation {
    #[schema(value_type = Object)]
    pub statement: serde_json::Value,
    pub proof: Vec<u8>,
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
