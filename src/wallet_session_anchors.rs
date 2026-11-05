//! Durable wallet-session anchors (A13 M1, DESIGN-secure-convenience 3.4): one row per wallet
//! session family in the wallet's (global) database, modelled on `cvld_stamp_uses`. A passkey
//! login (or a device bind on a passkey session) anchors its family to (member, C, K); renewal
//! and every request of a renewed session read the row, so a server restart never turns a live
//! renewal chain into a prompt. Only revocation, logout or eviction removes a row; there is no
//! age limit (2026-10-23: only revocation ends a chain).
use crate::error::{Error, Result};
use ckyh::Uuid;
use crlt::{Value, params};

/// Append after the global migration history. The family (32 random server bytes) is the key.
pub const SCHEMA: &str = "CREATE TABLE cvld_wallet_session_anchors (
    community_id TEXT NOT NULL,
    family BLOB NOT NULL CHECK (length(family) = 32),
    member TEXT NOT NULL CHECK (length(member) = 36),
    credential BLOB NOT NULL CHECK (length(credential) BETWEEN 1 AND 1024),
    device_key BLOB NOT NULL CHECK (length(device_key) = 32),
    community TEXT NOT NULL CHECK (length(community) BETWEEN 1 AND 64),
    anchored_at INTEGER NOT NULL CHECK (anchored_at >= 0),
    PRIMARY KEY (community_id, family)
) WITHOUT ROWID;
CREATE INDEX cvld_wallet_session_anchors_key
    ON cvld_wallet_session_anchors (community_id, member, device_key, anchored_at);";

/// Live families per K: installs that share one synced passkey derive the same K and each hold
/// their own family. A further anchor of the same K evicts the oldest.
pub const ANCHORS_PER_KEY: usize = 4;
/// Bound on all anchor rows of one wallet.
pub const CAPACITY: usize = 100_000;

/// One anchor: the family a passkey session of credential C opened, bound to K.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// The authenticating host's passkey community (the wallet's).
    pub community: String,
    pub member: Uuid,
    pub credential: ckyh::CredentialID,
    pub device_key: [u8; 32],
    pub anchored_at: u64,
}

fn storage(_: crlt::Error) -> Error {
    Error::Unavailable
}

fn time(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Invalid)
}

fn blob(row: &crlt::Row, index: usize) -> Result<Vec<u8>> {
    match row.get_value(index).map_err(storage)? {
        Value::Blob(bytes) => Ok(bytes.clone()),
        _ => Err(Error::Unavailable),
    }
}

fn bytes32(row: &crlt::Row, index: usize) -> Result<[u8; 32]> {
    blob(row, index)?.try_into().map_err(|_| Error::Unavailable)
}

/// The anchors of one Auth. Only the wallet host has a store; every other host keeps none, so
/// no anchor (and no renewal) exists there.
#[derive(Default)]
pub(crate) struct Anchors {
    store: Option<crlt::Community>,
}

impl Anchors {
    /// The wallet's durable anchors in `store` (the global database scope).
    pub fn durable(store: crlt::Community) -> Self {
        Self { store: Some(store) }
    }

    /// The anchor of `family`, if one exists. One indexed read.
    pub async fn get(&self, family: &[u8; 32]) -> Result<Option<Anchor>> {
        let Some(store) = &self.store else {
            return Ok(None);
        };
        let rows = store
            .query(
                "SELECT member, credential, device_key, community, anchored_at
                 FROM cvld_wallet_session_anchors WHERE family = ?1",
                params![family.to_vec()],
            )
            .await
            .map_err(storage)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        Ok(Some(Anchor {
            member: Uuid::parse_str(row.get_str(0).map_err(storage)?)
                .map_err(|_| Error::Unavailable)?,
            credential: blob(row, 1)?.into(),
            device_key: bytes32(row, 2)?,
            community: row.get_str(3).map_err(storage)?.to_owned(),
            anchored_at: u64::try_from(row.get_i64(4).map_err(storage)?)
                .map_err(|_| Error::Unavailable)?,
        }))
    }

    /// Anchor `family` (replacing its previous anchor), evicting this K's oldest families past
    /// `ANCHORS_PER_KEY`, in one transaction. A host without a store refuses.
    pub async fn insert(&self, family: [u8; 32], anchor: &Anchor) -> Result<()> {
        let store = self.store.as_ref().ok_or(Error::Forbidden)?;
        let member = anchor.member.to_string();
        let mut tx = store.tx().await.map_err(storage)?;
        tx.execute(
            "DELETE FROM cvld_wallet_session_anchors WHERE family = ?1",
            params![family.to_vec()],
        )
        .await
        .map_err(storage)?;
        let same = tx
            .query(
                "SELECT family FROM cvld_wallet_session_anchors
                 WHERE member = ?1 AND device_key = ?2 ORDER BY anchored_at",
                params![member.clone(), anchor.device_key.to_vec()],
            )
            .await
            .map_err(storage)?;
        let evict = same.len().saturating_sub(ANCHORS_PER_KEY - 1);
        for row in same.iter().take(evict) {
            tx.execute(
                "DELETE FROM cvld_wallet_session_anchors WHERE family = ?1",
                params![bytes32(row, 0)?.to_vec()],
            )
            .await
            .map_err(storage)?;
        }
        let count = tx
            .query("SELECT COUNT(*) FROM cvld_wallet_session_anchors", ())
            .await
            .map_err(storage)?
            .first()
            .ok_or(Error::Unavailable)?
            .get_i64(0)
            .map_err(storage)?;
        if !u64::try_from(count).is_ok_and(|count| count < CAPACITY as u64) {
            tx.rollback().await.map_err(storage)?;
            return Err(Error::Throttled);
        }
        tx.execute(
            "INSERT INTO cvld_wallet_session_anchors
             (family, member, credential, device_key, community, anchored_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                family.to_vec(),
                member,
                anchor.credential.as_ref().to_vec(),
                anchor.device_key.to_vec(),
                anchor.community.clone(),
                time(anchor.anchored_at)?
            ],
        )
        .await
        .map_err(storage)?;
        tx.commit().await.map_err(storage)
    }

    /// Logout (= explicit lock) ends one family for good.
    pub async fn forget_family(&self, family: &[u8; 32]) -> Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        store
            .execute(
                "DELETE FROM cvld_wallet_session_anchors WHERE family = ?1",
                params![family.to_vec()],
            )
            .await
            .map_err(storage)
            .map(drop)
    }

    /// Every family of one member ends (account logout, self-ban).
    pub async fn forget_member(&self, member: Uuid) -> Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        store
            .execute(
                "DELETE FROM cvld_wallet_session_anchors WHERE member = ?1",
                params![member.to_string()],
            )
            .await
            .map_err(storage)
            .map(drop)
    }

    /// Remove the anchors of `member` that `retired` selects and return their families, so their
    /// sessions end too. `retired(credential, K)` sees each anchor of the member once.
    pub async fn forget_where(
        &self,
        member: Uuid,
        retired: impl Fn(&[u8], &[u8; 32]) -> bool,
    ) -> Result<Vec<[u8; 32]>> {
        let Some(store) = &self.store else {
            return Ok(Vec::new());
        };
        let member = member.to_string();
        let mut tx = store.tx().await.map_err(storage)?;
        let rows = tx
            .query(
                "SELECT family, credential, device_key FROM cvld_wallet_session_anchors
                 WHERE member = ?1",
                params![member],
            )
            .await
            .map_err(storage)?;
        let mut families = Vec::new();
        for row in &rows {
            if retired(&blob(row, 1)?, &bytes32(row, 2)?) {
                let family = bytes32(row, 0)?;
                tx.execute(
                    "DELETE FROM cvld_wallet_session_anchors WHERE family = ?1",
                    params![family.to_vec()],
                )
                .await
                .map_err(storage)?;
                families.push(family);
            }
        }
        tx.commit().await.map_err(storage)?;
        Ok(families)
    }
}
