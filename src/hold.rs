//! Legal hold: the data of a community that Root ended under a legal order is
//! kept only as ciphertext that a root key opens. The hub holds the PUBLIC key
//! alone, so no running process can read a held community. HPKE (RFC 9180, base
//! mode, DHKEM(X25519, HKDF-SHA256), ChaCha20-Poly1305) through the same
//! `hpke` crate the voucher links use; nothing here is a primitive of our own.
use crate::error::{Error, Result};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};

type Kem = X25519HkdfSha256;

const INFO: &[u8] = b"cvld.hold.v1";

/// Seal `plaintext` to the holder of the root hold key. `bound` (the community id)
/// is authenticated, so a sealed blob cannot be passed off for another community.
pub fn seal(public: &[u8; 32], bound: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let public = <Kem as KemTrait>::PublicKey::from_bytes(public).map_err(|_| Error::Invalid)?;
    let (encapped, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &public,
        INFO,
        plaintext,
        bound,
    )
    .map_err(|_| Error::Unavailable)?;
    let mut sealed = encapped.to_bytes().to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Open a sealed blob with the root hold secret (offline tooling and tests; the
/// hub never holds this key).
pub fn open(secret: &[u8; 32], bound: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    let private = <Kem as KemTrait>::PrivateKey::from_bytes(secret).map_err(|_| Error::Invalid)?;
    let split = <Kem as KemTrait>::EncappedKey::size();
    if sealed.len() <= split {
        return Err(Error::Invalid);
    }
    let encapped =
        <Kem as KemTrait>::EncappedKey::from_bytes(&sealed[..split]).map_err(|_| Error::Invalid)?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &private,
        &encapped,
        INFO,
        &sealed[split..],
        bound,
    )
    .map_err(|_| Error::Refused)
}

/// A fresh hold key pair `(secret, public)`; the secret belongs offline to Root.
pub fn generate() -> ([u8; 32], [u8; 32]) {
    let (secret, public) = <Kem as KemTrait>::gen_keypair();
    let mut out = ([0u8; 32], [0u8; 32]);
    out.0.copy_from_slice(&secret.to_bytes());
    out.1.copy_from_slice(&public.to_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_root_secret_opens_what_the_hub_sealed() {
        let (secret, public) = generate();
        let sealed = seal(&public, b"community-1", b"held rows").unwrap();
        assert!(!sealed.windows(9).any(|w| w == b"held rows"));
        assert_eq!(
            open(&secret, b"community-1", &sealed).unwrap(),
            b"held rows"
        );
        // Another community, another key, or a flipped bit never opens.
        assert!(open(&secret, b"community-2", &sealed).is_err());
        let (other, _) = generate();
        assert!(open(&other, b"community-1", &sealed).is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&secret, b"community-1", &tampered).is_err());
    }
}
