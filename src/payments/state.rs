//! Caller-owned durable payment metadata. Provider continuation is RAM-only.
use super::{Amount, Error, Result};
use cpmt::{
    cost,
    payments::{Journal, Record, State},
};
use crlt::{Db, params};
use std::sync::Arc;

mod journal;

pub const SCHEMA: &str = r#"
CREATE TABLE cvld_payment_budget (
 community_id TEXT NOT NULL, id TEXT NOT NULL,
 identity TEXT NOT NULL, key_id BLOB,
 unit TEXT NOT NULL, scale INTEGER NOT NULL,
 maximum INTEGER NOT NULL CHECK(maximum >= 0),
 exposure INTEGER NOT NULL CHECK(exposure >= 0),
 poisoned INTEGER NOT NULL CHECK(poisoned IN (0,1)),
 PRIMARY KEY(community_id,id)
) WITHOUT ROWID;
CREATE TABLE cvld_payment_operation (
 community_id TEXT NOT NULL, id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision >= 0),
 deadline INTEGER NOT NULL CHECK(deadline >= 0),
 metadata TEXT NOT NULL,
 PRIMARY KEY(community_id,id)
) WITHOUT ROWID;
CREATE TABLE cvld_payment_receipt (
 community_id TEXT NOT NULL, id BLOB NOT NULL, owner BLOB NOT NULL,
 PRIMARY KEY(community_id,id)
) WITHOUT ROWID;
"#;

#[derive(Clone)]
pub struct DurableJournal {
    db: crlt::Community,
    clock: Arc<dyn cost::Clock>,
    record_bytes: usize,
}
fn storage(_: impl std::fmt::Debug) -> cpmt::payments::Error {
    cpmt::payments::Error::Storage
}
fn integer(value: u64) -> cpmt::payments::Result<i64> {
    i64::try_from(value).map_err(storage)
}
fn exposure(record: &Record) -> cpmt::payments::Result<u64> {
    let fee = record.cost();
    if fee.violation.is_some()
        || matches!(
            record.state(),
            State::Unknown | State::Pending | State::RequiresAction
        )
    {
        Ok(fee.maximum)
    } else {
        Ok(fee.actual.unwrap_or(fee.maximum))
    }
}

impl DurableJournal {
    pub(crate) fn use_clock(&mut self, clock: Arc<dyn cost::Clock>) {
        self.clock = clock;
    }
    /// `identity` is a maintained keyed commitment to the configured exact
    /// account/mode/endpoint. It contains no provider credential or raw request.
    /// Apply SCHEMA through the caller's full migration sequence before this.
    pub async fn new(
        db: &Db,
        community: &str,
        identity: &cpmt::payments::AccountIdentity,
        budget: &Amount,
        capacity: usize,
        record_bytes: usize,
        clock: Arc<dyn cost::Clock>,
    ) -> Result<Self> {
        if capacity == 0 || record_bytes == 0 {
            return Err(Error::Configuration);
        }
        let bytes = identity.as_bytes();
        let identity = format!(
            "{}{}",
            uuid::Uuid::from_slice(&bytes[..16])
                .map_err(|_| Error::Configuration)?
                .simple(),
            uuid::Uuid::from_slice(&bytes[16..])
                .map_err(|_| Error::Configuration)?
                .simple()
        );
        budget.domain()?;
        let db = db.community(community).map_err(|_| Error::Storage)?;
        let mut tx = db.tx().await.map_err(|_| Error::Storage)?;
        let rows = tx.query("SELECT identity,unit,scale,maximum,exposure FROM cvld_payment_budget WHERE id = ?1", ["fees"]).await.map_err(|_| Error::Storage)?;
        if let Some(row) = rows.first() {
            if row.get_str(0).map_err(|_| Error::Storage)? != identity
                || row.get_str(1).map_err(|_| Error::Storage)? != budget.unit
                || row.get_i64(2).map_err(|_| Error::Storage)? != i64::from(budget.scale)
                || row.get_i64(4).map_err(|_| Error::Storage)? > budget.atoms as i64
            {
                return Err(Error::Configuration);
            }
            tx.execute(
                "UPDATE cvld_payment_budget SET maximum = ?1 WHERE id = ?2",
                params![budget.atoms as i64, "fees"],
            )
            .await
            .map_err(|_| Error::Storage)?;
        } else {
            let old = tx
                .query("SELECT id FROM cvld_payment_operation LIMIT 1", ())
                .await
                .map_err(|_| Error::Storage)?;
            if !old.is_empty() {
                return Err(Error::Configuration);
            }
            tx.execute("INSERT INTO cvld_payment_budget(id,identity,unit,scale,maximum,exposure,poisoned) VALUES (?1,?2,?3,?4,?5,?6,?7)", params!["fees", identity.clone(), budget.unit.clone(), i64::from(budget.scale), budget.atoms as i64, 0, 0]).await.map_err(|_| Error::Storage)?;
        }
        tx.commit().await.map_err(|_| Error::Storage)?;
        Ok(Self {
            db,
            clock,
            record_bytes,
        })
    }
    fn encode(&self, record: &Record) -> cpmt::payments::Result<String> {
        let encoded = serde_json::to_string(&record.without_continuation()).map_err(storage)?;
        if encoded.len() > self.record_bytes {
            return Err(cpmt::payments::Error::Storage);
        }
        Ok(encoded)
    }
    fn decode(&self, encoded: &str) -> cpmt::payments::Result<Record> {
        if encoded.len() > self.record_bytes {
            return Err(cpmt::payments::Error::Storage);
        }
        let record: Record = serde_json::from_str(encoded).map_err(storage)?;
        // A durable row containing an unapproved continuation is corruption,
        // never a reason to expose a provider reference or silently bless it.
        if serde_json::from_str::<serde_json::Value>(encoded).map_err(storage)?
            != serde_json::to_value(record.without_continuation()).map_err(storage)?
        {
            return Err(cpmt::payments::Error::Storage);
        }
        Ok(record)
    }
}
