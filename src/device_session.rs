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

// The stamp scope of a community is `cpsd::StampScope::of_community` over
// `csgn::community_fingerprint`; server and device both build it there.
