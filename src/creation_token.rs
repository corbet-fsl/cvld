//! Blind creation tokens: the protocol is `cvld-client`'s; the issuance and
//! nullifier store is the server's.
use crate::error::{Error, Result};
pub use cvld_client::creation_token::*;

pub use store::{Limits, SCHEMA, SIGNATURES_SCHEMA, Store};

mod store {
    use super::*;
    use crlt::{Community, params};

    /// Signatures already issued, so a repeated request for the same blinded message
    /// (a device interrupted before it stored the answer) is answered again without
    /// counting a second issuance. The issuer saw the blinded message and the person
    /// at issuance anyway; nothing here links a person to a community.
    pub const SIGNATURES_SCHEMA: &str = "CREATE TABLE cvld_creation_signatures (
    community_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    blinded_hash BLOB NOT NULL CHECK (length(blinded_hash) = 32),
    signature BLOB NOT NULL,
    issued_at INTEGER NOT NULL,
    PRIMARY KEY (community_id, subject, blinded_hash)
) WITHOUT ROWID;";

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

    fn digest(bytes: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).to_vec()
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

        /// The signature issued earlier for exactly this blinded message to `subject`.
        pub async fn replay(&self, subject: &str, blinded: &[u8]) -> Result<Option<Vec<u8>>> {
            let rows = self
                .scope
                .query(
                    "SELECT signature FROM cvld_creation_signatures WHERE subject = ?1 AND blinded_hash = ?2",
                    params![subject, digest(blinded)],
                )
                .await
                .map_err(db)?;
            match rows.first() {
                None => Ok(None),
                Some(row) => match row.get_value(0).map_err(db)? {
                    crlt::Value::Blob(bytes) => Ok(Some(bytes.clone())),
                    _ => Err(Error::Unavailable),
                },
            }
        }

        /// Keep an issued signature for replay for a year (the issuance window).
        pub async fn remember(
            &self,
            subject: &str,
            blinded: &[u8],
            signature: &[u8],
            now: u64,
        ) -> Result<()> {
            let mut tx = self.scope.tx().await.map_err(db)?;
            let year_start = i64::try_from(now.saturating_sub(YEAR)).map_err(db)?;
            tx.execute(
                "DELETE FROM cvld_creation_signatures WHERE issued_at <= ?1",
                [year_start],
            )
            .await
            .map_err(db)?;
            let known = tx
                .query(
                    "SELECT issued_at FROM cvld_creation_signatures WHERE subject = ?1 AND blinded_hash = ?2",
                    params![subject, digest(blinded)],
                )
                .await
                .map_err(db)?;
            if !known.is_empty() {
                return tx.commit().await.map_err(db);
            }
            tx.execute(
                "INSERT INTO cvld_creation_signatures (subject, blinded_hash, signature, issued_at) VALUES (?1, ?2, ?3, ?4)",
                params![subject, digest(blinded), signature.to_vec(), i64::try_from(now).map_err(db)?],
            )
            .await
            .map_err(db)?;
            tx.commit().await.map_err(db)
        }

        /// The shell a token's nullifier is reserved for, and whether it is spent.
        pub async fn reservation(
            &self,
            nullifier: [u8; MESSAGE_LEN],
        ) -> Result<Option<([u8; 16], bool)>> {
            let rows = self
                .scope
                .query(
                    "SELECT shell, spent FROM cvld_creation_tokens WHERE nullifier = ?1",
                    [nullifier.to_vec()],
                )
                .await
                .map_err(db)?;
            let Some(row) = rows.first() else {
                return Ok(None);
            };
            let shell = match row.get_value(0).map_err(db)? {
                crlt::Value::Blob(bytes) => <[u8; 16]>::try_from(bytes.as_slice()).map_err(db)?,
                _ => return Err(Error::Unavailable),
            };
            Ok(Some((shell, row.get_i64(1).map_err(db)? != 0)))
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
