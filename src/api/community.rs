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
    pub lobby: Lobby,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PinRequest {
    pub field: String,
    #[schema(value_type = PinEnvelope)]
    pub pin: cmnt::cmbr::PinV2,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PinChange {
    pub field: String,
    #[schema(value_type = PinEnvelope)]
    pub pin: cmnt::cmbr::PinV2,
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
    pub schema: cmnt::cplc::cshm::Schema,
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
    pub manifest: Vec<u8>,
    pub settings: Vec<u8>,
    pub schema: Vec<u8>,
    pub schema_versions: Vec<u8>,
    pub communities: Vec<u8>,
    pub revocations: Vec<u8>,
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
