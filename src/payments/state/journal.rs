//! Atomic budget, operation and receipt decisions for the real domain journal.
use super::*;

impl Journal for DurableJournal {
    async fn bind(&self, key_id: &[u8; 32]) -> cpmt::payments::Result<()> {
        let mut tx = self.db.tx().await.map_err(storage)?;
        let rows = tx
            .query(
                "SELECT key_id FROM cvld_payment_budget WHERE id = ?1",
                ["fees"],
            )
            .await
            .map_err(storage)?;
        let row = rows.first().ok_or(cpmt::payments::Error::Storage)?;
        match row.get_value(0).map_err(storage)? {
            crlt::Value::Null => {
                tx.execute(
                    "UPDATE cvld_payment_budget SET key_id = ?1 WHERE id = ?2",
                    params![key_id.to_vec(), "fees"],
                )
                .await
                .map_err(storage)?;
            }
            crlt::Value::Blob(previous) if previous.as_slice() == key_id => (),
            _ => return Err(cpmt::payments::Error::KeyMismatch),
        }
        tx.commit().await.map_err(storage)
    }
    async fn get(&self, key: &str) -> cpmt::payments::Result<Option<Record>> {
        let observed = self.clock.now();
        let rows = self
            .db
            .query(
                "SELECT metadata FROM cvld_payment_operation WHERE id = ?1",
                [key],
            )
            .await
            .map_err(storage)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let completed = self.clock.now();
        if completed < observed {
            return Err(cpmt::payments::Error::Expired);
        }
        Ok(Some(self.decode(row.get_str(0).map_err(storage)?)?))
    }

    async fn begin(
        &self,
        key: &str,
        record: &Record,
        deadline: u64,
        clock: &dyn cost::Clock,
    ) -> cpmt::payments::Result<Option<Record>> {
        let observed = clock.now();
        let mut tx = self.db.tx().await.map_err(storage)?;
        let now = clock.now();
        if now < observed || now >= deadline {
            return Err(cpmt::payments::Error::Expired);
        }
        let previous = tx
            .query(
                "SELECT metadata FROM cvld_payment_operation WHERE id = ?1",
                [key],
            )
            .await
            .map_err(storage)?;
        if let Some(row) = previous.first() {
            return Ok(Some(self.decode(row.get_str(0).map_err(storage)?)?));
        }
        let rows = tx.query("SELECT unit,scale,maximum,exposure,poisoned,key_id FROM cvld_payment_budget WHERE id = ?1", ["fees"]).await.map_err(storage)?;
        let row = rows.first().ok_or(cpmt::payments::Error::Storage)?;
        let fee = record.cost();
        if row.get_str(0).map_err(storage)? != fee.unit
            || row.get_i64(1).map_err(storage)? != i64::from(fee.scale)
            || row.get_i64(4).map_err(storage)? != 0
            || !matches!(row.get_value(5).map_err(storage)?, crlt::Value::Blob(_))
            || fee.violation.is_some()
            || fee.actual.is_some()
            || record.state() != State::Unknown
            || record.revision() != 0
        {
            return Err(cpmt::payments::Error::Cost);
        }
        let used = row.get_i64(3).map_err(storage)?;
        let total = used
            .checked_add(integer(fee.maximum)?)
            .ok_or(cpmt::payments::Error::Cost)?;
        if used < 0 || total > row.get_i64(2).map_err(storage)? {
            return Err(cpmt::payments::Error::Cost);
        }
        let metadata = self.encode(record)?;
        let final_time = clock.now();
        if final_time < now || final_time >= deadline {
            return Err(cpmt::payments::Error::Expired);
        }
        tx.execute("INSERT INTO cvld_payment_operation(id,revision,deadline,metadata) VALUES (?1,?2,?3,?4)", params![key, 0, integer(deadline)?, metadata]).await.map_err(storage)?;
        tx.execute(
            "UPDATE cvld_payment_budget SET exposure = ?1 WHERE id = ?2",
            params![total, "fees"],
        )
        .await
        .map_err(storage)?;
        let before_commit = clock.now();
        if before_commit < final_time || before_commit >= deadline {
            return Err(cpmt::payments::Error::Expired);
        }
        tx.commit().await.map_err(storage)?;
        // Committed late reservations stay uncertain and retain exposure.
        let after_commit = clock.now();
        if after_commit < before_commit || after_commit >= deadline {
            return Err(cpmt::payments::Error::Expired);
        }
        Ok(None)
    }
    async fn replace(
        &self,
        key: &str,
        expected_revision: u64,
        record: &Record,
    ) -> cpmt::payments::Result<()> {
        if record.revision()
            != expected_revision
                .checked_add(1)
                .ok_or(cpmt::payments::Error::Storage)?
        {
            return Err(cpmt::payments::Error::Conflict);
        }
        let mut tx = self.db.tx().await.map_err(storage)?;
        let rows = tx
            .query(
                "SELECT metadata,revision FROM cvld_payment_operation WHERE id = ?1",
                [key],
            )
            .await
            .map_err(storage)?;
        let row = rows.first().ok_or(cpmt::payments::Error::Conflict)?;
        if row.get_i64(1).map_err(storage)? != integer(expected_revision)? {
            return Err(cpmt::payments::Error::Conflict);
        }
        let old = self.decode(row.get_str(0).map_err(storage)?)?;
        // Only domain-owned replacements enter here. Immutable exact request
        // fields must nevertheless survive a faulty host/store implementation.
        let before = serde_json::to_value(&old).map_err(storage)?;
        let after = serde_json::to_value(record.without_continuation()).map_err(storage)?;
        for field in ["fingerprint", "owner"] {
            if before[field] != after[field] {
                return Err(cpmt::payments::Error::Conflict);
            }
        }
        for field in [
            "request_digest",
            "sandbox",
            "id",
            "adapter",
            "operation",
            "binding",
        ] {
            if before["outcome"][field] != after["outcome"][field] {
                return Err(cpmt::payments::Error::Conflict);
            }
        }
        for field in ["unit", "scale", "maximum", "source"] {
            if before["cost"][field] != after["cost"][field] {
                return Err(cpmt::payments::Error::Conflict);
            }
        }
        if let Some((receipt, owner)) = record.receipt() {
            let receipts = tx
                .query(
                    "SELECT owner FROM cvld_payment_receipt WHERE id = ?1",
                    params![receipt.to_vec()],
                )
                .await
                .map_err(storage)?;
            if let Some(saved) = receipts.first() {
                match saved.get_value(0).map_err(storage)? {
                    crlt::Value::Blob(previous) if previous.as_slice() == owner => (),
                    _ => return Err(cpmt::payments::Error::Conflict),
                }
            } else {
                tx.execute(
                    "INSERT INTO cvld_payment_receipt(id,owner) VALUES (?1,?2)",
                    params![receipt.to_vec(), owner.to_vec()],
                )
                .await
                .map_err(storage)?;
            }
        }
        let budgets = tx
            .query(
                "SELECT exposure,poisoned FROM cvld_payment_budget WHERE id = ?1",
                ["fees"],
            )
            .await
            .map_err(storage)?;
        let budget = budgets.first().ok_or(cpmt::payments::Error::Storage)?;
        let used = budget.get_i64(0).map_err(storage)?;
        let previous_exposure = integer(exposure(&old)?)?;
        let next_exposure = integer(exposure(record)?)?;
        let next = used
            .checked_sub(previous_exposure)
            .and_then(|used| used.checked_add(next_exposure))
            .filter(|used| *used >= 0)
            .ok_or(cpmt::payments::Error::Storage)?;
        let poisoned = i64::from(
            budget.get_i64(1).map_err(storage)? != 0 || record.cost().violation.is_some(),
        );
        tx.execute(
            "UPDATE cvld_payment_budget SET exposure = ?1,poisoned = ?2 WHERE id = ?3",
            params![next, poisoned, "fees"],
        )
        .await
        .map_err(storage)?;
        tx.execute(
            "UPDATE cvld_payment_operation SET revision = ?1,metadata = ?2 WHERE id = ?3",
            params![integer(record.revision())?, self.encode(record)?, key],
        )
        .await
        .map_err(storage)?;
        tx.commit().await.map_err(storage)?;
        Ok(())
    }
}
