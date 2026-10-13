//! The founding-key (genesis) document of a community incarnation, kept so the
//! community's feed can publish it. It is written once, when the community's
//! signer is created, and never changes.
use crate::error::{Error, Result};
use crlt::{Db, params};

pub const SCHEMA: &str = "CREATE TABLE cvld_genesis (
    community_id TEXT NOT NULL,
    singleton INTEGER NOT NULL CHECK (singleton = 1),
    document BLOB NOT NULL CHECK (length(document) BETWEEN 1 AND 4096),
    PRIMARY KEY (community_id, singleton)
) WITHOUT ROWID;";

/// Record the document once. A second, different document is refused.
pub async fn store(db: &Db, scope: &str, document: &[u8]) -> Result<()> {
    let mut tx = db.tx(scope).await.map_err(Error::Unavailable.redact())?;
    let rows = tx
        .query(
            "SELECT document FROM cvld_genesis WHERE singleton = ?1",
            [1],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    if let Some(row) = rows.first() {
        let same = matches!(
            row.get_value(0).map_err(Error::Unavailable.redact())?,
            crlt::Value::Blob(bytes) if bytes.as_slice() == document
        );
        tx.rollback().await.map_err(Error::Unavailable.redact())?;
        return if same { Ok(()) } else { Err(Error::Refused) };
    }
    tx.execute(
        "INSERT INTO cvld_genesis (singleton, document) VALUES (?1, ?2)",
        params![1, document.to_vec()],
    )
    .await
    .map_err(Error::Unavailable.redact())?;
    tx.commit().await.map_err(Error::Unavailable.redact())
}

/// The recorded document, absent for a community created before genesis existed.
pub async fn load(db: &Db, scope: &str) -> Result<Option<Vec<u8>>> {
    let rows = db
        .community(scope)
        .map_err(Error::Invalid.redact())?
        .query(
            "SELECT document FROM cvld_genesis WHERE singleton = ?1",
            [1],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    match rows.first() {
        None => Ok(None),
        Some(row) => match row.get_value(0).map_err(Error::Unavailable.redact())? {
            crlt::Value::Blob(bytes) => Ok(Some(bytes.clone())),
            _ => Err(Error::Unavailable),
        },
    }
}
