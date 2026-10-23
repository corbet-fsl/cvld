//! The bytes a device signs to open a community session. The server keeps only the nonce, so
//! the message is rebuilt identically on both sides and binds the community and the time.

/// One-use nonce length in bytes.
pub const NONCE_LEN: usize = 32;
/// Seconds a nonce stays valid after it is issued.
pub const NONCE_SECONDS: u64 = 60;

/// Signed message: domain tag, community, nonce, issue time.
pub fn message(community: &str, nonce: &[u8; NONCE_LEN], issued: u64) -> Vec<u8> {
    let mut message = b"cvld.device-session.v1\0".to_vec();
    message.extend_from_slice(&(community.len() as u16).to_be_bytes());
    message.extend_from_slice(community.as_bytes());
    message.extend_from_slice(nonce);
    message.extend_from_slice(&issued.to_be_bytes());
    message
}

/// Signed message of an admin session: like [`message`] with its own domain tag, so a signature
/// for a member session never opens an admin session.
pub fn garden_message(community: &str, nonce: &[u8; NONCE_LEN], issued: u64) -> Vec<u8> {
    let mut message = message(community, nonce, issued);
    message.splice(
        0..b"cvld.device-session.v1\0".len(),
        b"cvld.garden-session.v1\0".iter().copied(),
    );
    message
}

/// Stamp action kind of an admin session; the payload digest is [`garden_payload`].
pub const GARDEN_ACTION: &str = "garden_session";

/// Payload digest of an admin session's stamp action: SHA-256(device key || nonce), so the stamp
/// covers exactly this key and this one-use attempt.
pub fn garden_payload(device_key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"cvld.garden-session.payload.v1\0");
    hasher.update(device_key);
    hasher.update(nonce);
    hasher.finalize().into()
}

/// Stamp action kind of a device join; the payload digest is [`join_payload`].
pub const JOIN_ACTION: &str = "device_join";

/// Payload digest of a device join's stamp action: SHA-256(device key || seed), where `seed`
/// is the member's opaque initial creation commitment (Keys enrollment seed). One stamp thus
/// approves the key and the creation it will anchor.
pub fn join_payload(device_key: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(device_key);
    hasher.update(seed);
    hasher.finalize().into()
}

/// Pairing step one (API action `device_add`): register the key PENDING, with the pairing
/// stamp's approval. It is the step number 1 of [`pairing_message`].
pub const ADD_ACTION: &str = "device_add";
/// Pairing step two (API action `device_activate`): activate the PENDING key once its lineage
/// revision is published. It needs no stamp, and is the step number 2 of [`pairing_message`].
pub const ACTIVATE_ACTION: &str = "device_activate";
/// Stamp action kind of the ONE pairing stamp slot per community, presented once at
/// `device_add`; the payload digest is [`pair_payload`]. All slots of a stamp come from one
/// user verification, so separate add, activate and revision digests would carry no extra
/// approval: the one digest covers the whole pairing and `device_activate` needs no stamp.
pub const PAIR_ACTION: &str = "device_pair";

/// Payload digest of a community's pairing stamp slot: SHA-256 over the domain tag, then
/// length-prefixed `community`, the member's `member_id` (pseudonym), the NEW `device_key`, the
/// community's own opaque pairing `session` value, and the planned lineage `revision` (a flag
/// byte, then its 32-byte digest when planned). The stamp therefore approves exactly this key
/// for this member in this community within this pairing, and, when the host knows the
/// revision at stamp time, the revision that will carry the key too.
///
/// `session` is one value PER community: a value shared across communities would link a
/// member's memberships. When no revision is planned yet the digest still commits to the key,
/// which is what activation needs: the key alone decides what the server may activate, and the
/// revision only decides what the lineage publishes, which its own evidence checks.
pub fn pair_payload(
    community: &str,
    member_id: &str,
    device_key: &[u8; 32],
    session: &[u8; 32],
    revision: Option<&[u8; 32]>,
) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"cvld.device-pair.v1\0");
    for text in [community, member_id] {
        hasher.update((text.len() as u16).to_be_bytes());
        hasher.update(text.as_bytes());
    }
    hasher.update(device_key);
    hasher.update(session);
    match revision {
        Some(revision) => {
            hasher.update([1]);
            hasher.update(revision);
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

/// Signed message of a device join: domain tag, community, passport challenge id, device key.
pub fn join_message(community: &str, challenge: &str, device_key: &[u8; 32]) -> Vec<u8> {
    let mut message = b"cvld.device-join.v1\0".to_vec();
    message.extend_from_slice(&(community.len() as u16).to_be_bytes());
    message.extend_from_slice(community.as_bytes());
    message.extend_from_slice(&(challenge.len() as u16).to_be_bytes());
    message.extend_from_slice(challenge.as_bytes());
    message.extend_from_slice(device_key);
    message
}

/// Domain tag of a pairing step's proof of possession; the tag of ckmg's
/// `DevicePurpose::PairingPossession`, so a join, session or salt signature is never one.
pub const POSSESSION_TAG: &[u8] = b"cvld.device-pairing-possession.v1\0";

/// Signed message of a pairing step's proof of possession by the NEW key: domain tag, step
/// (`device_add` = 1, `device_activate` = 2), community, challenge and device key. It is
/// exactly `ckmg::PairingPossession::message`, which the pairing guest signs; the step is in
/// the message, so an add signature is no activate signature and neither is a join signature.
/// An unknown `kind` yields a message no honest device signs.
pub fn pairing_message(
    kind: &str,
    community: &str,
    challenge: &str,
    device_key: &[u8; 32],
) -> Vec<u8> {
    let step: u8 = match kind {
        ADD_ACTION => 1,
        ACTIVATE_ACTION => 2,
        _ => 0,
    };
    let mut message = POSSESSION_TAG.to_vec();
    message.push(step);
    message.extend_from_slice(&(community.len() as u16).to_be_bytes());
    message.extend_from_slice(community.as_bytes());
    message.extend_from_slice(&(challenge.len() as u16).to_be_bytes());
    message.extend_from_slice(challenge.as_bytes());
    message.extend_from_slice(device_key);
    message
}

// The stamp scope of a community is `cpsd::StampScope::of_community` over
// `csgn::community_fingerprint`; server and device both build it there.
