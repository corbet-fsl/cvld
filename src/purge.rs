//! Deleting everything a community scope holds, as one transaction. Used when a
//! community ends and when a creation is rolled back. The table list comes from
//! the community migration history, so no table can be forgotten.
use crate::error::{Error, Result};

/// Names of every table the community migrations create, in creation order.
fn tables() -> Vec<String> {
    let mut names = Vec::new();
    for migration in crate::service::community_migrations() {
        let sql = migration.sql.to_owned();
        let mut rest = sql.as_str();
        while let Some(at) = rest.find("CREATE TABLE ") {
            rest = &rest[at + "CREATE TABLE ".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                names.push(name);
            }
        }
    }
    names
}

/// Delete every row of `scope` in every community table.
pub async fn purge_scope(db: &crlt::Db, scope: &str) -> Result<()> {
    let mut tx = db.tx(scope).await.map_err(Error::Unavailable.redact())?;
    for table in tables().iter().rev() {
        tx.execute(&format!("DELETE FROM {table}"), ())
            .await
            .map_err(Error::Unavailable.redact())?;
    }
    tx.commit().await.map_err(Error::Unavailable.redact())
}

/// Every row of `scope` in every community table, as one JSON document. Used only
/// to seal the data of a community under a legal hold (`hold::seal`) before the
/// scope is purged.
pub async fn dump_scope(db: &crlt::Db, scope: &str) -> Result<Vec<u8>> {
    let mut tx = db.tx(scope).await.map_err(Error::Unavailable.redact())?;
    let mut document = serde_json::Map::new();
    for table in tables() {
        let rows = tx
            .query(&format!("SELECT * FROM {table}"), ())
            .await
            .map_err(Error::Unavailable.redact())?;
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                serde_json::Value::Array(
                    row.columns()
                        .iter()
                        .zip(row.values())
                        .map(|(name, value)| serde_json::json!([name, cell(value)]))
                        .collect(),
                )
            })
            .collect();
        if !rows.is_empty() {
            document.insert(table, serde_json::Value::Array(rows));
        }
    }
    tx.rollback().await.map_err(Error::Unavailable.redact())?;
    serde_json::to_vec(&document).map_err(Error::Unavailable.redact())
}

fn cell(value: &crlt::Value) -> serde_json::Value {
    use crlt::Value;
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Integer(number) => serde_json::json!({ "i": number }),
        Value::Real(number) => serde_json::json!({ "r": number }),
        Value::Text(text) => serde_json::json!({ "t": text }),
        Value::Blob(bytes) => {
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            serde_json::json!({ "b": hex })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_list_covers_the_known_tables() {
        let names = tables();
        for expected in ["cvld_genesis", "cvld_service", "cmbr_creation"] {
            assert!(names.iter().any(|n| n == expected), "{expected}");
        }
    }

    #[tokio::test]
    async fn purge_removes_one_scope_and_keeps_another() {
        let dir = tempfile::tempdir().unwrap();
        let config = crlt::Config::new(format!("file://{}", dir.path().join("p.db").display()), "");
        let db = crlt::Db::open(config).await.unwrap();
        db.migrate(&crate::service::community_migrations())
            .await
            .unwrap();
        crate::genesis_store::store(&db, "firstone1", b"one")
            .await
            .unwrap();
        crate::genesis_store::store(&db, "secondone", b"two")
            .await
            .unwrap();
        purge_scope(&db, "firstone1").await.unwrap();
        assert!(
            crate::genesis_store::load(&db, "firstone1")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            crate::genesis_store::load(&db, "secondone").await.unwrap(),
            Some(b"two".to_vec())
        );
    }
}
