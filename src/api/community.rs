use super::{PresentationInput, StepUpProof};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// Original registered-key certificate with its actual checked output time.
/// The signed certificate is unchanged; this observation is from the fresh
/// authenticated server response, not retained prior device observations.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeyCertificateResponse {
    pub bytes: Vec<u8>,
    pub checked_at: u64,
}

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
    /// Original target-Policy first-Root entitlement, redeemed with full gates.
    #[serde(default)]
    pub creation: Option<Vec<u8>>,
    /// Original target-Policy FounderAdmin entitlement, redeemed with full gates.
    #[serde(default)]
    pub founder: Option<Vec<u8>>,
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
    /// Required except for Root, whose portal sign-in is the step-up.
    #[serde(default)]
    pub step_up: Option<StepUpProof>,
}

/// Account-owned management metadata, without keys, counters or last-use data.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeyView {
    pub credential: Vec<u8>,
    pub created_year: u16,
    pub created_month: u8,
    pub authenticator_type: Option<String>,
    pub revoked: bool,
    pub current: bool,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeyList {
    pub passkeys: Vec<PasskeyView>,
}
impl PasskeyList {
    pub(crate) fn from_records(
        records: Vec<ckyh::StoredPasskey>,
        current: &ckyh::CredentialID,
    ) -> Self {
        Self {
            passkeys: records
                .into_iter()
                .map(|record| PasskeyView {
                    credential: record.credential_id().as_ref().to_vec(),
                    created_year: record.created().year(),
                    created_month: record.created().month(),
                    authenticator_type: record.authenticator_type().map(str::to_owned),
                    revoked: record.is_revoked(),
                    current: record.credential_id() == current,
                })
                .collect(),
        }
    }
}

/// Bind one actual lineage device key to the current passkey.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceKey {
    pub key: [u8; 32],
    /// Required except for Root, whose portal sign-in is the step-up.
    #[serde(default)]
    pub step_up: Option<StepUpProof>,
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
/// Wire form of the additional-passkey request: starting it needs a fresh
/// user-verifying assertion bound to this exact action.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum AddPasskeyRequest {
    Begin {
        /// Required except for Root, whose portal sign-in is the step-up.
        #[serde(default)]
        step_up: Option<Box<StepUpProof>>,
    },
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
    },
}
