use super::*;

/// The one account-authority action a fresh passkey assertion authorizes. The
/// assertion is bound to this exact value, the session and the host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepUpAction {
    /// Begin registering another passkey for this account.
    PasskeyAdd,
    /// Revoke this exact passkey.
    PasskeyRevoke { credential: Vec<u8> },
    /// Authorize this exact device signing key.
    DeviceAuthorize { key: [u8; 32] },
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StepUpStart {
    pub action: StepUpAction,
}

/// A user-verifying assertion challenge for exactly one action. Single use.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StepUpChallenge {
    pub ceremony: String,
    /// Exclusive deadline of this challenge.
    pub expires: u64,
    pub options: Value,
}

/// The completed assertion that accompanies the authorized action.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StepUpProof {
    pub ceremony: String,
    #[schema(value_type = std::collections::BTreeMap<String, Value>, additional_properties = true)]
    pub credential: ckyh::PublicKeyCredential,
}
