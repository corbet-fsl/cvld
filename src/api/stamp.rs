//! Confirmation stamps (one-confirmation model): wallet issuance and the community join that
//! binds a member's first device key with a passport presentation plus one stamp.
use super::*;

/// A single-use stamp nonce reserved for this wallet session, with the wallet's stamp key.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StampChallenge {
    /// cpsd issuance challenge (32 bytes).
    pub challenge: Vec<u8>,
    /// cpsd stamp public key encoding (cohort included).
    pub key: Vec<u8>,
    /// WebAuthn request options of this session's wallet passkey. The device replaces the
    /// challenge with the request's confirmation challenge; the options carry no authority.
    #[schema(value_type = Object)]
    pub options: serde_json::Value,
}

/// The public signed fields of one user-verifying WebAuthn assertion of the wallet passkey.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnAssertion {
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(default)]
    pub user_handle: Option<Vec<u8>>,
}

/// One stamp request: the challenge, the cpsd request and the assertion whose WebAuthn
/// challenge is exactly the request's confirmation challenge. Without an assertion only the
/// account's first stamp, under the birth grant (C5).
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StampIssue {
    pub challenge: Vec<u8>,
    pub request: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion: Option<WebAuthnAssertion>,
}

/// Join a community by device key: a passport presentation over a challenge of this
/// community, a stamp presentation covering `device_join` with payload
/// [`crate::device_session::join_payload`] of exactly `device_key` and `seed`, and the device
/// key's signature over [`crate::device_session::join_message`].
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceJoin {
    pub passport: PresentationInput,
    /// cpsd stamp presentation encoding.
    pub stamp: Vec<u8>,
    /// The stamp action's salt.
    pub salt: [u8; 32],
    pub device_key: [u8; 32],
    /// The member's opaque initial creation commitment (nonzero), held by this first key for
    /// `initial_creation` and `initial_publication_bind`.
    pub seed: [u8; 32],
    pub signature: Vec<u8>,
}

/// The member the joined device key belongs to (open sessions with `device_session_*`).
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceJoined {
    pub user: String,
}

/// Pairing step one: a passport presentation over a challenge of this community, the
/// community's ONE pairing stamp slot (`device_pair`, payload
/// [`crate::device_session::pair_payload`] of exactly this community, the passport's
/// pseudonym, `device_key`, `session` and `revision`) and the new key's signature over
/// [`crate::device_session::pairing_message`] of step `device_add` (proof of possession). The
/// server registers the key PENDING and keeps the approval with it; activation needs no stamp.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceAdd {
    pub passport: PresentationInput,
    /// cpsd stamp presentation encoding.
    pub stamp: Vec<u8>,
    /// The stamp action's salt.
    pub salt: [u8; 32],
    pub device_key: [u8; 32],
    /// This community's own opaque pairing session value (never shared across communities).
    pub session: [u8; 32],
    /// Digest of the lineage revision planned for the key, when known at stamp time.
    pub revision: Option<[u8; 32]>,
    pub signature: Vec<u8>,
}

/// Pairing step two: a passport presentation over a challenge of this community and the new
/// key's signature over [`crate::device_session::pairing_message`] of step `device_activate`
/// (proof of possession). No stamp: the PENDING key that `device_add` registered for the same
/// community, pseudonym and key is the approval, and it expires after
/// [`cmty::cmbr::PAIRING_PENDING_SECONDS`].
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceActivate {
    pub passport: PresentationInput,
    pub device_key: [u8; 32],
    pub signature: Vec<u8>,
}
