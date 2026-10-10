use super::*;

/// Explicit purpose displayed before the holder confirms with their passkey.
/// Permanent global self-ban ends access through this wallet forever. There is
/// no undo, recovery or operator override; burned uniqueness remains consumed.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SelfBanIntent {
    PermanentGlobalSelfBan,
    PermanentCommunitySelfBan,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfBanChallenge {
    pub ceremony: String,
    pub intent: SelfBanIntent,
    /// Display before requesting the confirming passkey assertion.
    pub warning: String,
    /// Exclusive confirmation deadline; the operation cannot be undone.
    pub expires: u64,
    pub options: Value,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfBanConfirmation {
    pub ceremony: String,
    #[schema(value_type = std::collections::BTreeMap<String, Value>, additional_properties = true)]
    pub credential: ckyh::PublicKeyCredential,
}

/// Read only the holder's committed permanent self-ban, without restoring access.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfBanStatus {
    pub self_banned: bool,
}

/// Dedicated discoverable authentication for outcome inspection, never login.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfBanStatusChallenge {
    pub ceremony: String,
    pub expires: u64,
    pub options: Value,
}
