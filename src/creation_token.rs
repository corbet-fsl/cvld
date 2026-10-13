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

#[cfg(feature = "server")]
pub use store::{Limits, SCHEMA, Store};

#[cfg(feature = "server")]
mod store {
    use super::*;
    use crlt::{Community, params};

    pub const SCHEMA: &str = "CREATE TABLE cvld_creation_issued (
    community_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    seq INTEGER NOT NULL,
    issued_at INTEGER NOT NULL,
    PRIMARY KEY (community_id, subject, seq)
) WITHOUT ROWID;
CREATE TABLE cvld_creation_tokens (
    community_id TEXT NOT NULL,
    nullifier BLOB NOT NULL CHECK (length(nullifier) = 32),
    shell BLOB NOT NULL CHECK (length(shell) = 16),
    spent INTEGER NOT NULL CHECK (spent IN (0, 1)),
    PRIMARY KEY (community_id, nullifier)
) WITHOUT ROWID;
CREATE INDEX cvld_creation_tokens_shell ON cvld_creation_tokens (community_id, shell);";

    const WEEK: u64 = 7 * 86_400;
    const YEAR: u64 = 365 * 86_400;

    /// Issuance limits per person; defaults are the platform values.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Limits {
        pub per_week: u32,
        pub per_year: u32,
    }

    impl Default for Limits {
        fn default() -> Self {
            Self {
                per_week: 1,
                per_year: 12,
            }
        }
    }

    fn db<T>(_: T) -> Error {
        Error::Unavailable
    }

    /// Global-scope issuance counter and nullifier set.
    pub struct Store {
        scope: Community,
        limits: Limits,
    }

    impl Store {
        pub fn new(scope: Community, limits: Limits) -> Self {
            Self { scope, limits }
        }

        /// Count and record one issuance for `subject`, or refuse when a limit
        /// is reached. Counting is per person and keeps no community link.
        pub async fn record_issuance(&self, subject: &str, now: u64) -> Result<()> {
            let mut tx = self.scope.tx().await.map_err(db)?;
            let year_start = i64::try_from(now.saturating_sub(YEAR)).map_err(db)?;
            tx.execute(
                "DELETE FROM cvld_creation_issued WHERE subject = ?1 AND issued_at <= ?2",
                params![subject, year_start],
            )
            .await
            .map_err(db)?;
            let rows = tx
                .query(
                    "SELECT seq, issued_at FROM cvld_creation_issued WHERE subject = ?1",
                    [subject],
                )
                .await
                .map_err(db)?;
            let week_start = i64::try_from(now.saturating_sub(WEEK)).map_err(db)?;
            let mut last = 0;
            let mut week = 0u32;
            for row in &rows {
                last = last.max(row.get_i64(0).map_err(db)?);
                if row.get_i64(1).map_err(db)? > week_start {
                    week += 1;
                }
            }
            if week >= self.limits.per_week || rows.len() >= self.limits.per_year as usize {
                tx.rollback().await.map_err(db)?;
                return Err(Error::Throttled);
            }
            tx.execute(
                "INSERT INTO cvld_creation_issued (subject, seq, issued_at) VALUES (?1, ?2, ?3)",
                params![subject, last + 1, i64::try_from(now).map_err(db)?],
            )
            .await
            .map_err(db)?;
            tx.commit().await.map_err(db)
        }

        /// Reserve a verified token's nullifier for one community shell.
        pub async fn reserve(&self, nullifier: [u8; MESSAGE_LEN], shell: [u8; 16]) -> Result<()> {
            let mut tx = self.scope.tx().await.map_err(db)?;
            let known = tx
                .query(
                    "SELECT spent FROM cvld_creation_tokens WHERE nullifier = ?1",
                    [nullifier.to_vec()],
                )
                .await
                .map_err(db)?;
            if !known.is_empty() {
                tx.rollback().await.map_err(db)?;
                return Err(Error::Refused);
            }
            tx.execute(
                "INSERT INTO cvld_creation_tokens (nullifier, shell, spent) VALUES (?1, ?2, 0)",
                params![nullifier.to_vec(), shell.to_vec()],
            )
            .await
            .map_err(db)?;
            tx.commit().await.map_err(db)
        }

        /// The community went live: the token is spent for good.
        pub async fn spend(&self, shell: [u8; 16]) -> Result<()> {
            let mut tx = self.scope.tx().await.map_err(db)?;
            let changed = tx
                .execute(
                    "UPDATE cvld_creation_tokens SET spent = 1 WHERE shell = ?1 AND spent = 0",
                    [shell.to_vec()],
                )
                .await
                .map_err(db)?;
            tx.commit().await.map_err(db)?;
            if changed == 1 {
                Ok(())
            } else {
                Err(Error::Refused)
            }
        }

        /// Creation failed or the shell expired: the token is usable again.
        pub async fn release(&self, shell: [u8; 16]) -> Result<()> {
            let mut tx = self.scope.tx().await.map_err(db)?;
            tx.execute(
                "DELETE FROM cvld_creation_tokens WHERE shell = ?1 AND spent = 0",
                [shell.to_vec()],
            )
            .await
            .map_err(db)?;
            tx.commit().await.map_err(db)
        }
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

    #[cfg(feature = "server")]
    mod store {
        use super::super::*;

        async fn store(limits: Limits) -> (tempfile::TempDir, Store) {
            let dir = tempfile::tempdir().unwrap();
            let config =
                crlt::Config::new(format!("file://{}", dir.path().join("t.db").display()), "");
            let db = crlt::Db::open(config).await.unwrap();
            db.migrate(&[crlt::Migration::new(1, "tokens", SCHEMA)])
                .await
                .unwrap();
            (dir, Store::new(db.community("global").unwrap(), limits))
        }

        #[tokio::test]
        async fn one_per_week_and_twelve_per_year_per_person() {
            let (_dir, store) = store(Limits::default()).await;
            let day = 86_400;
            store.record_issuance("alice", 1_000_000).await.unwrap();
            assert_eq!(
                store.record_issuance("alice", 1_000_000 + 6 * day).await,
                Err(Error::Throttled)
            );
            // Another person is unaffected.
            store.record_issuance("bob", 1_000_000).await.unwrap();
            let mut at = 1_000_000;
            for _ in 0..11 {
                at += 8 * day;
                store.record_issuance("alice", at).await.unwrap();
            }
            at += 8 * day;
            // Twelve issuances lie within the last 365 days (12 * 8 = 96 days).
            assert_eq!(
                store.record_issuance("alice", at).await,
                Err(Error::Throttled)
            );
            // After a year the oldest ones age out.
            store
                .record_issuance("alice", at + 365 * day)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn nullifier_is_reserved_spent_or_released() {
            let (_dir, store) = store(Limits::default()).await;
            store.reserve([5; 32], [1; 16]).await.unwrap();
            assert_eq!(store.reserve([5; 32], [2; 16]).await, Err(Error::Refused));
            store.release([1; 16]).await.unwrap();
            store.reserve([5; 32], [2; 16]).await.unwrap();
            store.spend([2; 16]).await.unwrap();
            // A spent token stays spent: release does nothing, reserve refuses.
            store.release([2; 16]).await.unwrap();
            assert_eq!(store.reserve([5; 32], [3; 16]).await, Err(Error::Refused));
            assert_eq!(store.spend([2; 16]).await, Err(Error::Refused));
        }
    }
}
