//! Blind creation tokens (RFC 9474 blind RSA). The global service issues a token
//! to an authenticated global account at most once per rolling week and a bounded
//! number of times per rolling year, counting per person at issuance. The token
//! is redeemed (spent as a nullifier) when a community is created, so the
//! platform never learns which person created which community. The key is used
//! for this purpose only. The protocol functions are pure and also serve the
//! browser client.
use crate::error::{Error, Result};
use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, MessageRandomizer, PublicKeySha384PSSRandomized,
    SecretKeySha384PSSRandomized, Signature,
};
use serde::{Deserialize, Serialize};

pub type PublicKey = PublicKeySha384PSSRandomized;
pub type SecretKey = SecretKeySha384PSSRandomized;

/// Length of the random token message, which is also the spent nullifier.
pub const MESSAGE_LEN: usize = 32;

/// A finished token as presented at community creation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub message: Vec<u8>,
    pub randomizer: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Client state between blinding and finishing; never leaves the device.
pub struct Pending {
    blinding: BlindingResult,
    message: [u8; MESSAGE_LEN],
}

/// What a device must keep between sending a blinded message and finishing the
/// token, so an interruption never loses a token the issuer already counted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingState {
    pub message: Vec<u8>,
    pub blinded: Vec<u8>,
    pub secret: Vec<u8>,
    pub randomizer: Option<[u8; 32]>,
}

impl Pending {
    /// The state to keep in custody. It is a secret of the device.
    pub fn to_state(&self) -> PendingState {
        PendingState {
            message: self.message.to_vec(),
            blinded: self.blinding.blind_message.0.clone(),
            secret: self.blinding.secret.0.clone(),
            randomizer: self.blinding.msg_randomizer.map(|value| value.0),
        }
    }

    /// Restore kept state; a malformed record is refused.
    pub fn from_state(state: PendingState) -> Result<Self> {
        let message: [u8; MESSAGE_LEN] = state
            .message
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid)?;
        Ok(Self {
            blinding: BlindingResult {
                blind_message: blind_rsa_signatures::BlindMessage(state.blinded),
                secret: blind_rsa_signatures::Secret(state.secret),
                msg_randomizer: state.randomizer.map(MessageRandomizer),
            },
            message,
        })
    }

    /// The blinded message that was (or is to be) sent to the issuer.
    pub fn blinded(&self) -> &[u8] {
        &self.blinding.blind_message.0
    }
}

/// Parse the issuer's published public key.
pub fn public_key(der: &[u8]) -> Result<PublicKey> {
    PublicKey::from_der(der).map_err(|_| Error::Invalid)
}

/// Client: blind a fresh random `message` for the issuer's public key.
/// Returns the state to keep and the blinded message to send.
pub fn request(key: &PublicKey, message: [u8; MESSAGE_LEN]) -> Result<(Pending, Vec<u8>)> {
    let blinding = key
        .blind(&mut DefaultRng, message)
        .map_err(|_| Error::Invalid)?;
    let blinded = blinding.blind_message.0.clone();
    Ok((Pending { blinding, message }, blinded))
}

/// Client: unblind the issuer's answer into a verified token.
pub fn finish(key: &PublicKey, pending: Pending, blind_signature: &[u8]) -> Result<Token> {
    let signature = key
        .finalize(
            &BlindSignature(blind_signature.to_vec()),
            &pending.blinding,
            pending.message,
        )
        .map_err(|_| Error::Invalid)?;
    let randomizer = pending
        .blinding
        .msg_randomizer
        .ok_or(Error::Invalid)?
        .0
        .to_vec();
    Ok(Token {
        message: pending.message.to_vec(),
        randomizer,
        signature: signature.0,
    })
}

/// Anyone with the public key: check a presented token.
pub fn verify(key: &PublicKey, token: &Token) -> Result<[u8; MESSAGE_LEN]> {
    let message: [u8; MESSAGE_LEN] = token
        .message
        .as_slice()
        .try_into()
        .map_err(|_| Error::Invalid)?;
    let randomizer: [u8; 32] = token
        .randomizer
        .as_slice()
        .try_into()
        .map_err(|_| Error::Invalid)?;
    key.verify(
        &Signature(token.signature.clone()),
        Some(MessageRandomizer(randomizer)),
        message,
    )
    .map_err(|_| Error::Unauthorized)?;
    Ok(message)
}

/// Server: the issuing key, used for creation tokens only.
pub struct Issuer {
    secret: SecretKey,
    public: PublicKey,
}

impl Issuer {
    pub fn from_der(secret_der: &[u8]) -> Result<Self> {
        let secret = SecretKey::from_der(secret_der).map_err(|_| Error::Invalid)?;
        let public = secret.public_key().map_err(|_| Error::Invalid)?;
        Ok(Self { secret, public })
    }

    pub fn public_der(&self) -> Result<Vec<u8>> {
        self.public.to_der().map_err(|_| Error::Unavailable)
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Sign a blinded message. The caller has already checked the quota.
    pub fn sign(&self, blinded: &[u8]) -> Result<Vec<u8>> {
        self.secret
            .blind_sign(blinded)
            .map(|signature| signature.0)
            .map_err(|_| Error::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blind_rsa_signatures::KeyPairSha384PSSRandomized as KeyPair;

    fn issuer() -> Issuer {
        let pair = KeyPair::generate(&mut DefaultRng, 2048).unwrap();
        Issuer::from_der(&pair.sk.to_der().unwrap()).unwrap()
    }

    #[test]
    fn blind_issue_finish_verify_round_trip() {
        let issuer = issuer();
        let key = public_key(&issuer.public_der().unwrap()).unwrap();
        let (pending, blinded) = request(&key, [9; MESSAGE_LEN]).unwrap();
        let signature = issuer.sign(&blinded).unwrap();
        let token = finish(&key, pending, &signature).unwrap();
        assert_eq!(verify(issuer.public(), &token).unwrap(), [9; MESSAGE_LEN]);
        // The finished token is not the blinded request the issuer saw.
        assert_ne!(token.signature, signature);
    }

    #[test]
    fn forged_or_altered_tokens_are_refused() {
        let issuer = issuer();
        let other = self::issuer();
        let key = public_key(&issuer.public_der().unwrap()).unwrap();
        let (pending, blinded) = request(&key, [1; MESSAGE_LEN]).unwrap();
        let token = finish(&key, pending, &issuer.sign(&blinded).unwrap()).unwrap();
        assert!(verify(other.public(), &token).is_err());
        let mut changed = token.clone();
        changed.message[0] ^= 1;
        assert!(verify(issuer.public(), &changed).is_err());
        let mut short = token;
        short.message.pop();
        assert_eq!(verify(issuer.public(), &short), Err(Error::Invalid));
    }
}
