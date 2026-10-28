//! The Balance owner uses the door's existing scoped CRLT transaction.
use cblc::{
    Error,
    storage::{AccountStorage, AtomicTransaction, CommitDeadline, CurrentRecord, Transaction},
};
use crlt::{Community, Db, params};
use tokio::runtime::{Handle, RuntimeFlavor};

pub(crate) const SCHEMA: &str = "
CREATE TABLE cvld_account_current (
    community_id TEXT NOT NULL,
    key BLOB NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (community_id, key)
) WITHOUT ROWID;
";

/// Only the native Balance worker may call this synchronous adapter. It retains
/// the original database capability/runtime; it opens neither a DB nor runtime.
pub(crate) struct Store {
    scope: Community,
    runtime: Handle,
}
impl Store {
    pub(crate) fn new(db: &Db, community: &str, runtime: Handle) -> Result<Self, Error> {
        if runtime.runtime_flavor() != RuntimeFlavor::MultiThread {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            scope: db.community(community).map_err(|_| Error::Storage)?,
            runtime,
        })
    }

    /// After the actual ledger's checked initialization, its durable clock must
    /// exist. Missing/malformed data is never a zero floor on an existing store.
    #[cfg(test)]
    pub(crate) fn durable_floor(&mut self) -> Result<u64, Error> {
        let mut tx = self.transaction()?;
        let floor = tx.get::<u64>(b"clock")?.ok_or(Error::Storage)?;
        tx.rollback()?;
        Ok(floor)
    }
}
impl AccountStorage for Store {
    fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        let transaction = self
            .runtime
            .block_on(self.scope.tx())
            .map_err(|_| Error::Storage)?;
        Ok(Transaction::new(Box::new(HostTransaction {
            transaction: Some(transaction),
            runtime: self.runtime.clone(),
        })))
    }
}

struct HostTransaction {
    // The original CRLT owner rolls back an uncommitted transaction on drop,
    // including after error or cancellation. No callback can commit it early.
    transaction: Option<crlt::Transaction>,
    runtime: Handle,
}
impl HostTransaction {
    fn transaction(&mut self) -> &mut crlt::Transaction {
        self.transaction
            .as_mut()
            .expect("taken only by the consuming commit/rollback")
    }
}
fn blob(row: &crlt::Row, column: usize) -> Result<Vec<u8>, Error> {
    match row.get_value(column).map_err(|_| Error::Storage)? {
        crlt::Value::Blob(value) => Ok(value.clone()),
        _ => Err(Error::Storage),
    }
}
impl AtomicTransaction for HostTransaction {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let runtime = self.runtime.clone();
        let rows = runtime
            .block_on(self.transaction().query(
                "SELECT value FROM cvld_account_current WHERE key = ?1",
                params![key.to_vec()],
            ))
            .map_err(|_| Error::Storage)?;
        rows.first().map(|row| blob(row, 0)).transpose()
    }

    fn current_range(
        &mut self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<CurrentRecord>, Error> {
        if start >= end || limit == 0 || limit > (1 << 20) + 1 {
            return Err(Error::InvalidInput);
        }
        let runtime = self.runtime.clone();
        let mut cursor = start.to_vec();
        let mut first = true;
        let mut result = Vec::new();
        // Door uses CRLT Config::new's 10,000-row query cap. Read 1,000-row
        // pages under the SAME immediate transaction. A caller with a lower
        // CRLT cap receives Storage; never retry its poisoned transaction or
        // present a truncated page as the complete serialized snapshot.
        while result.len() < limit as usize {
            let remaining = (limit as usize - result.len()).min(1000) as i64;
            let sql = if first {
                "SELECT key,value FROM cvld_account_current WHERE key >= ?1 AND key < ?2 ORDER BY key LIMIT ?3"
            } else {
                "SELECT key,value FROM cvld_account_current WHERE key > ?1 AND key < ?2 ORDER BY key LIMIT ?3"
            };
            let rows = runtime
                .block_on(
                    self.transaction()
                        .query(sql, params![cursor.clone(), end.to_vec(), remaining]),
                )
                .map_err(|_| Error::Storage)?;
            let count = rows.len();
            for row in rows {
                let key = blob(&row, 0)?;
                if key.as_slice() < start || key.as_slice() >= end || (!first && key <= cursor) {
                    return Err(Error::Storage);
                }
                cursor = key.clone();
                first = false;
                result.push((key, blob(&row, 1)?));
            }
            if count < remaining as usize {
                break;
            }
        }
        Ok(result)
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let runtime = self.runtime.clone();
        let tx = self.transaction();
        runtime
            .block_on(async {
                let count = tx
                    .execute(
                        "UPDATE cvld_account_current SET value = ?1 WHERE key = ?2",
                        params![value.to_vec(), key.to_vec()],
                    )
                    .await?;
                if count == 0 {
                    tx.execute(
                        "INSERT INTO cvld_account_current(key,value) VALUES (?1,?2)",
                        params![key.to_vec(), value.to_vec()],
                    )
                    .await?;
                }
                Ok::<_, crlt::Error>(())
            })
            .map_err(|_| Error::Storage)
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        let runtime = self.runtime.clone();
        runtime
            .block_on(self.transaction().execute(
                "DELETE FROM cvld_account_current WHERE key = ?1",
                params![key.to_vec()],
            ))
            .map(|_| ())
            .map_err(|_| Error::Storage)
    }

    fn commit(mut self: Box<Self>) -> Result<(), Error> {
        let tx = self
            .transaction
            .take()
            .expect("consuming commit takes it exactly once");
        self.runtime
            .block_on(tx.commit())
            .map_err(|_| Error::Storage)
    }

    fn commit_before(mut self: Box<Self>, deadline: &CommitDeadline<'_>) -> Result<(), Error> {
        // All business writes above hold CRLT's original BEGIN IMMEDIATE lock.
        // Choose the live logical commit time and store its opaque clock record
        // in this same transaction; only physical persistence follows.
        let (key, value) = deadline.commit_record()?;
        self.put(key, &value)?;
        self.commit()
    }

    fn rollback(mut self: Box<Self>) -> Result<(), Error> {
        let tx = self
            .transaction
            .take()
            .expect("consuming rollback takes it exactly once");
        self.runtime
            .block_on(tx.rollback())
            .map_err(|_| Error::Storage)
    }
}

#[cfg(test)]
#[path = "storage/tests.rs"]
mod tests;
