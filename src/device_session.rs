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
