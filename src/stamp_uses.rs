//! The community's one-use record of stamped actions (cpsd `StampLedger` store), in its OWN
//! table with its OWN capacity, so stamped actions never compete with login or passport
//! challenges for `cpsd_challenges` capacity (REVIEW-stamp L3). Key = action digest; a record
//! lives until its stamp expires (plus the ledger's prune margin).
use crlt::params;

/// Append after the community migration history.
pub const SCHEMA: &str = "CREATE TABLE cvld_stamp_uses (
    community_id TEXT NOT NULL,
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    binding BLOB NOT NULL CHECK (length(binding) = 32),
    expires INTEGER NOT NULL CHECK (expires > 0),
    PRIMARY KEY (community_id, digest)
) WITHOUT ROWID;
CREATE INDEX cvld_stamp_uses_expiry ON cvld_stamp_uses (community_id, expires);";

/// Default bound on live records per community: far above one confirmation per member and day.
pub const DEFAULT_CAPACITY: usize = 100_000;

pub struct StampUses {
    community: cpsd::CommunityId,
    db: crlt::Community,
    capacity: usize,
}

impl StampUses {
    pub fn new(
        db: &crlt::Db,
        community: &str,
        capacity: usize,
    ) -> crate::error::Result<Self> {
        use crate::error::Error;
        if capacity == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            community: cpsd::CommunityId::new(community).map_err(Error::Invalid.redact())?,
            db: db.community(community).map_err(Error::Invalid.redact())?,
            capacity,
        })
    }
}

fn storage(_: crlt::Error) -> cpsd::Error {
    cpsd::Error::Storage
}

fn time(value: u64) -> Result<i64, cpsd::Error> {
    i64::try_from(value).map_err(|_| cpsd::Error::Storage)
}

impl cpsd::ChallengeStore for StampUses {
    fn community(&self) -> &cpsd::CommunityId {
        &self.community
    }
    async fn reserve(&self, record: cpsd::ChallengeRecord) -> Result<bool, cpsd::Error> {
        let expires = time(record.expires)?;
        let mut tx = self.db.tx().await.map_err(storage)?;
        if !tx
            .query(
                "SELECT 1 FROM cvld_stamp_uses WHERE digest = ?1",
                params![record.nonce.to_vec()],
            )
            .await
            .map_err(storage)?
            .is_empty()
        {
            tx.rollback().await.map_err(storage)?;
            return Ok(false);
        }
        let rows = tx
            .query("SELECT COUNT(*) FROM cvld_stamp_uses", ())
            .await
            .map_err(storage)?;
        let count = rows
            .first()
            .ok_or(cpsd::Error::Storage)?
            .get_i64(0)
            .map_err(storage)?;
        if !u64::try_from(count).is_ok_and(|count| count < self.capacity as u64) {
            tx.rollback().await.map_err(storage)?;
            return Err(cpsd::Error::StorageCapacity);
        }
        tx.execute(
            "INSERT INTO cvld_stamp_uses (digest, binding, expires) VALUES (?1, ?2, ?3)",
            params![record.nonce.to_vec(), record.binding.to_vec(), expires],
        )
        .await
        .map_err(storage)?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }
    async fn matches(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: cpsd::Timestamp,
    ) -> Result<bool, cpsd::Error> {
        Ok(!self
            .db
            .query(
                "SELECT 1 FROM cvld_stamp_uses WHERE digest = ?1 AND binding = ?2 AND expires >= ?3",
                params![nonce.to_vec(), binding.to_vec(), time(now)?],
            )
            .await
            .map_err(storage)?
            .is_empty())
    }
    async fn consume(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: cpsd::Timestamp,
    ) -> Result<bool, cpsd::Error> {
        Ok(self
            .db
            .execute(
                "DELETE FROM cvld_stamp_uses WHERE digest = ?1 AND binding = ?2 AND expires >= ?3",
                params![nonce.to_vec(), binding.to_vec(), time(now)?],
            )
            .await
            .map_err(storage)?
            == 1)
    }
    async fn prune(&self, now: cpsd::Timestamp) -> Result<u64, cpsd::Error> {
        self.db
            .execute(
                "DELETE FROM cvld_stamp_uses WHERE expires < ?1",
                params![time(now)?],
            )
            .await
            .map_err(storage)
    }
}
