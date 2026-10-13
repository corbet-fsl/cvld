//! Bind a physical service database to one configured role and community.
use crate::error::{Error, Result};
use crlt::{Db, params};

pub const SCHEMA: &str = "CREATE TABLE cvld_service (
    community_id TEXT NOT NULL,
    singleton INTEGER NOT NULL CHECK (singleton = 1),
    kind TEXT NOT NULL,
    scope TEXT NOT NULL,
    PRIMARY KEY (community_id, singleton)
) WITHOUT ROWID;";

pub async fn bind(db: &Db, kind: &str, scope: &str) -> Result<()> {
    bind_in(db, "cvld:service", kind, scope).await
}

/// Bind one community of a database that the hub shares between communities:
/// each scope owns its own record, so the database as a whole is not tied to one.
pub async fn bind_shared(db: &Db, scope: &str) -> Result<()> {
    bind_in(db, &format!("cvld:service:{scope}"), "community", scope).await
}

async fn bind_in(db: &Db, key: &str, kind: &str, scope: &str) -> Result<()> {
    let mut tx = db.tx(key).await.map_err(Error::Unavailable.redact())?;
    let rows = tx
        .query(
            "SELECT kind, scope FROM cvld_service WHERE singleton = ?1",
            [1],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    if let Some(row) = rows.first() {
        if row.get_str(0).map_err(Error::Unavailable.redact())? != kind
            || row.get_str(1).map_err(Error::Unavailable.redact())? != scope
        {
            return Err(Error::Invalid);
        }
    } else {
        tx.execute(
            "INSERT INTO cvld_service (singleton, kind, scope) VALUES (?1, ?2, ?3)",
            params![1, kind, scope],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    }
    tx.commit().await.map_err(Error::Unavailable.redact())
}
