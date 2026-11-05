//! The community-signed Balance publication that named each record epoch, kept per
//! epoch so an accepted join-time ancestry can still be checked after the
//! community's current publication has moved on to a later epoch.
//!
//! It is public, already signed data: the store keeps the opaque envelope bytes and
//! the descriptor coordinates they were verified to name, nothing about members. A
//! later revision for the same epoch and root replaces the kept one (its signature
//! lasts longer); a different root for a kept epoch is never stored, so one epoch
//! always names one descriptor here. Every reader verifies the bytes again.
use crate::error::{Error, Result};
use crlt::{Db, params};

pub const SCHEMA: &str = "CREATE TABLE cvld_join_publication (
    community_id TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    root BLOB NOT NULL CHECK (length(root) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    publication BLOB NOT NULL CHECK (length(publication) BETWEEN 1 AND 1048576),
    PRIMARY KEY (community_id, epoch)
) WITHOUT ROWID;";

/// Keep `publication` as the one that names record epoch `epoch` with `root`,
/// unless a later or equal revision of the same descriptor is already kept. A kept
/// epoch with another root is left as it is.
pub async fn retain(
    db: &Db,
    scope: &str,
    epoch: u64,
    root: &[u8; 32],
    revision: u64,
    publication: &[u8],
) -> Result<()> {
    let epoch = i64::try_from(epoch).map_err(|_| Error::Invalid)?;
    let revision = i64::try_from(revision).map_err(|_| Error::Invalid)?;
    let mut tx = db.tx(scope).await.map_err(Error::Unavailable.redact())?;
    let rows = tx
        .query(
            "SELECT root, revision FROM cvld_join_publication WHERE epoch = ?1",
            [epoch],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    if let Some(row) = rows.first() {
        let same_root = matches!(
            row.get_value(0).map_err(Error::Unavailable.redact())?,
            crlt::Value::Blob(bytes) if bytes.as_slice() == root
        );
        let kept = match row.get_value(1).map_err(Error::Unavailable.redact())? {
            crlt::Value::Integer(kept) => *kept,
            _ => return Err(Error::Unavailable),
        };
        if !same_root || kept >= revision {
            tx.rollback().await.map_err(Error::Unavailable.redact())?;
            return Ok(());
        }
        tx.execute(
            "UPDATE cvld_join_publication SET revision = ?2, publication = ?3 WHERE epoch = ?1",
            params![epoch, revision, publication.to_vec()],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    } else {
        tx.execute(
            "INSERT INTO cvld_join_publication (epoch, root, revision, publication) \
             VALUES (?1, ?2, ?3, ?4)",
            params![epoch, root.to_vec(), revision, publication.to_vec()],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    }
    tx.commit().await.map_err(Error::Unavailable.redact())
}

/// The publication kept for record epoch `epoch` when it names `root`.
pub async fn load(db: &Db, scope: &str, epoch: u64, root: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    let epoch = i64::try_from(epoch).map_err(|_| Error::Invalid)?;
    let rows = db
        .community(scope)
        .map_err(Error::Invalid.redact())?
        .query(
            "SELECT root, publication FROM cvld_join_publication WHERE epoch = ?1",
            [epoch],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let same_root = matches!(
        row.get_value(0).map_err(Error::Unavailable.redact())?,
        crlt::Value::Blob(bytes) if bytes.as_slice() == root
    );
    match row.get_value(1).map_err(Error::Unavailable.redact())? {
        crlt::Value::Blob(bytes) if same_root => Ok(Some(bytes.clone())),
        crlt::Value::Blob(_) => Ok(None),
        _ => Err(Error::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("file://{}", dir.path().join("community.db").display());
        let db = Db::open(crlt::Config::new(url, "")).await.unwrap();
        db.migrate(&crate::service::community_migrations())
            .await
            .unwrap();
        (dir, db)
    }

    /// One epoch keeps one descriptor: the newest revision of the same root wins,
    /// an older revision never replaces it, and another root is never stored.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_epoch_keeps_the_newest_publication_of_one_descriptor() {
        let (_dir, db) = db().await;
        let scope = "community1";
        assert_eq!(load(&db, scope, 7, &[5; 32]).await.unwrap(), None);
        retain(&db, scope, 7, &[5; 32], 2, b"second").await.unwrap();
        assert_eq!(
            load(&db, scope, 7, &[5; 32]).await.unwrap().as_deref(),
            Some(&b"second"[..])
        );
        retain(&db, scope, 7, &[5; 32], 1, b"first").await.unwrap();
        retain(&db, scope, 7, &[5; 32], 3, b"third").await.unwrap();
        retain(&db, scope, 7, &[6; 32], 4, b"fork").await.unwrap();
        assert_eq!(
            load(&db, scope, 7, &[5; 32]).await.unwrap().as_deref(),
            Some(&b"third"[..])
        );
        assert_eq!(load(&db, scope, 7, &[6; 32]).await.unwrap(), None);
        // Another epoch and another community scope are separate.
        assert_eq!(load(&db, scope, 8, &[5; 32]).await.unwrap(), None);
        assert_eq!(load(&db, "community2", 7, &[5; 32]).await.unwrap(), None);
    }
}
