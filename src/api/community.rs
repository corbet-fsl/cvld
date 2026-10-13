use super::PresentationInput;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PresentationChallenge {
    pub challenge: String,
    pub request: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Handle {
    pub handle: String,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Available {
    pub available: bool,
}
/// Current local register role, not a credential or a public profile badge.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberRole {
    pub member: String,
    pub role: super::Role,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetMemberRole {
    /// Target's community pseudonym, as returned by the enrolment lobby.
    pub member: String,
    pub role: super::Role,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Lobby {
    pub member_id: String,
    pub state: String,
    pub handle: Option<String>,
    pub missing: Value,
    pub steps: Vec<Value>,
    pub warnings: Vec<LobbyWarning>,
    /// Passport proof is always fresh when requesting a community credential.
    pub passport_required: bool,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LobbyWarning {
    RegistrationExpires { deadline: i64 },
    AddSecondDeviceOrSyncedPasskey,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Voucher {
    pub id: String,
    pub member_binding: String,
    pub valid_until: u64,
    pub signature: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Withdraw {
    pub gate: String,
    pub provider: String,
    pub credential: CredentialRequest,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequest {
    pub presentation: PresentationInput,
    pub devices: Vec<[u8; 32]>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialResponse {
    pub credential: Option<Vec<u8>>,
    /// Original Policy-signed live passkey binding; present only with credential.
    pub passkey_binding: Option<Vec<u8>>,
    pub lobby: Lobby,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PinRequest {
    pub field: String,
    #[schema(value_type = PinEnvelope)]
    pub pin: cmty::cmbr::PinV2,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PinChange {
    pub field: String,
    #[schema(value_type = PinEnvelope)]
    pub pin: cmty::cmbr::PinV2,
    pub evidence: Vec<u8>,
}
/// Wire schema of cmbr's versioned pin capability; cmbr validates every binding.
#[derive(ToSchema)]
pub struct PinEnvelope {
    pub version: u8,
    pub community: String,
    pub member: String,
    pub field: String,
    pub fingerprint: [u8; 32],
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub field: String,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PinView {
    pub fingerprint: [u8; 32],
    pub revision: u64,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PinResponse {
    pub pin: Option<PinView>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Setting {
    pub key: String,
    /// Explicit null is a value. Set inherit to remove this layer's row.
    pub value: Value,
    pub inherit: bool,
    pub effective_at: u64,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlatformSetting {
    pub setting: Setting,
    pub force: bool,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SchemaRequest {
    #[schema(value_type = Object)]
    pub schema: cmty::cplc::cshm::Schema,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SchemaChanges {
    pub changes: Value,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustFeed {
    pub revision: u64,
    pub policy_epoch: u64,
    pub key_ring: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_transitions: Vec<TrustKeyTransition>,
    pub manifest: Vec<u8>,
    pub settings: Vec<u8>,
    pub schema: Vec<u8>,
    pub schema_versions: Vec<u8>,
    /// Original optional Policy publication, authenticated with the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_board: Option<Vec<u8>>,
    /// Original optional Balance publication, authenticated with the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<Vec<u8>>,
    pub communities: Vec<u8>,
    pub revocations: Vec<u8>,
}
/// Original publishing-key endorsement; routing metadata is not authority.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustKeyTransition {
    pub revision: u64,
    pub proof: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Since {
    pub revision: u64,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Announcement {
    pub revision: u64,
    pub policy_epoch: u64,
    pub changed: bool,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokePasskey {
    pub credential: Vec<u8>,
}

/// Bind one actual lineage device key to the current passkey.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceKey {
    pub key: [u8; 32],
}

/// Current public signing keys; the authenticated passkey authorizes mutations.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceKeys {
    pub keys: Vec<[u8; 32]>,
}

/// Both phases of one session-bound additional-passkey operation.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum AddPasskey {
    Begin,
    Finish {
        ceremony: String,
        #[schema(value_type = std::collections::BTreeMap<String, Value>, additional_properties = true)]
        credential: Box<ckyh::RegisterPublicKeyCredential>,
    },
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum AddedPasskey {
    Challenge {
        ceremony: String,
        user: String,
        options: Value,
    },
    Registered {
        user: String,
        credential: Vec<u8>,
        certificate: Vec<u8>,
    },
}

/// One layer row of a setting; the wrapper keeps "not set" apart from explicit null.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SettingLayer {
    pub value: Value,
    /// Platform rows only: override every lower layer.
    pub force: bool,
}
/// A catalogue entry with everything a generic settings screen needs.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SettingItem {
    pub key: String,
    pub group: String,
    pub label: String,
    pub help: String,
    pub unit: Option<String>,
    /// Switching off is permanent for earlier cases; ask for confirmation.
    pub one_way: bool,
    /// boolean, integer, number, string, array, object or policy.
    pub value_type: String,
    pub nullable: bool,
    pub min: Option<Value>,
    pub max: Option<Value>,
    /// platform, template, community or member: the deepest layer allowed to override.
    pub lowest_layer: String,
    pub default: Value,
    pub platform: Option<SettingLayer>,
    pub community: Option<SettingLayer>,
    /// The resolved value everyone sees.
    pub effective: Value,
    /// Whether the caller's role may edit this setting in its own layer.
    pub editable: bool,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SettingList {
    pub settings: Vec<SettingItem>,
}
