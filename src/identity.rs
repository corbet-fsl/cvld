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
    let mut tx = db
        .tx("cvld:service")
        .await
        .map_err(|_| Error::Unavailable)?;
    let rows = tx
        .query(
            "SELECT kind, scope FROM cvld_service WHERE singleton = ?1",
            [1],
        )
        .await
        .map_err(|_| Error::Unavailable)?;
    if let Some(row) = rows.first() {
        if row.get_str(0).map_err(|_| Error::Unavailable)? != kind
            || row.get_str(1).map_err(|_| Error::Unavailable)? != scope
        {
            return Err(Error::Invalid);
        }
    } else {
        tx.execute(
            "INSERT INTO cvld_service (singleton, kind, scope) VALUES (?1, ?2, ?3)",
            params![1, kind, scope],
        )
        .await
        .map_err(|_| Error::Unavailable)?;
    }
    tx.commit().await.map_err(|_| Error::Unavailable)
}
