//! Host-owned operational ledger. No destinations, codes, bodies or credentials.
use super::{Amount, Error, Outcome, Result};
use crate::service::Clock;
use cfbk::cost;
use crlt::{Db, params};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub const SCHEMA: &str = "CREATE TABLE cvld_contact_ceremony (
    community_id TEXT NOT NULL,
    ceremony BLOB NOT NULL,
    unit TEXT NOT NULL,
    scale INTEGER NOT NULL,
    budget INTEGER NOT NULL,
    exposure INTEGER NOT NULL,
    attempts INTEGER NOT NULL,
    maximum_attempts INTEGER NOT NULL,
    deadline INTEGER NOT NULL,
    PRIMARY KEY (community_id, ceremony)
) WITHOUT ROWID;
CREATE TABLE cvld_contact_dispatch (
    community_id TEXT NOT NULL,
    operation BLOB NOT NULL,
    ceremony BLOB NOT NULL,
    binding TEXT NOT NULL,
    maximum INTEGER NOT NULL,
    deadline INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    PRIMARY KEY (community_id, operation)
) WITHOUT ROWID;";

pub const BINDING_SCHEMA: &str = "CREATE TABLE cvld_contact_key_binding (
    community_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    scope TEXT NOT NULL,
    commitment TEXT NOT NULL,
    PRIMARY KEY (community_id, domain)
) WITHOUT ROWID;";
const KEY_GET: &str = "SELECT scope, commitment FROM cvld_contact_key_binding WHERE domain = ?1";
const KEY_INSERT: &str =
    "INSERT INTO cvld_contact_key_binding (domain, scope, commitment) VALUES (?1, ?2, ?3)";
const LEGACY_FINGERPRINT: &str = "SELECT entry_key FROM cgbl_record WHERE bucket = ?1 AND entry_key >= ?2 AND entry_key < ?3 AND value IS NOT NULL LIMIT 1";
const LEGACY_ACCOUNT: &str = "SELECT entry_key FROM cgbl_record WHERE bucket = ?1 AND json_type(value, ?2) IS NOT NULL LIMIT 1";

pub struct ComparisonBinding {
    pub domain: cgbl::contacts::ContactDomain,
    pub commitment: String,
}

const GET: &str = "SELECT unit, scale, budget, exposure, attempts, maximum_attempts, deadline FROM cvld_contact_ceremony WHERE ceremony = ?1";
const USED: &str = "SELECT binding FROM cvld_contact_dispatch WHERE operation = ?1";
const CREATE: &str = "INSERT INTO cvld_contact_ceremony (ceremony, unit, scale, budget, exposure, attempts, maximum_attempts, deadline) VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, ?6)";
const INCREASE: &str = "UPDATE cvld_contact_ceremony SET exposure = exposure + ?1, attempts = attempts + 1 WHERE ceremony = ?2 AND exposure <= budget - ?1 AND attempts < maximum_attempts";
const DISPATCH: &str = "INSERT INTO cvld_contact_dispatch (operation, ceremony, binding, maximum, deadline, outcome) VALUES (?1, ?2, ?3, ?4, ?5, 'uncertain')";
const COMPLETE: &str = "UPDATE cvld_contact_dispatch SET outcome = ?1 WHERE operation = ?2 AND ceremony = ?3 AND outcome = 'uncertain'";

/// Immutable authorization across all begin/fallback/check attempts. A RAM
/// cascade cannot reset these values, even after process loss.
pub struct Reservation {
    pub ceremony: [u8; 32],
    /// The leaf calls its authenticated contact binding a ceremony. Multiple
    /// configured provider bindings share the host ceremony budget above.
    pub leaf_binding: [u8; 32],
    pub operation: [u8; 32],
    pub binding: String,
    pub maximum: cost::Amount,
    pub budget: Amount,
    pub max_attempts: usize,
    pub ceremony_deadline: u64,
    pub dispatch_deadline: u64,
}

pub struct Ledger {
    db: crlt::Community,
    clock: Arc<dyn Clock>,
}
impl Ledger {
    /// Schema migration is the caller's responsibility alongside the other
    /// global schemas. Never opens a second database or changes its scope.
    pub fn new(db: &Db, scope: &str, clock: Arc<dyn Clock>) -> Result<Self> {
        Ok(Self {
            db: db.community(scope).map_err(|_| Error::Storage)?,
            clock,
        })
    }
    /// Install or compare both identity domains atomically before the host
    /// serves operations. Existing persisted domain identities without a marker
    /// require an explicit operator migration: no current key is silently blessed.
    pub async fn bind_comparison_keys(
        &self,
        scope: &str,
        bindings: &[ComparisonBinding],
    ) -> Result<()> {
        if bindings.is_empty() {
            return Ok(());
        }
        let mut tx = self.db.tx().await.map_err(|_| Error::Storage)?;
        for binding in bindings {
            if binding.commitment.len() != 64
                || !binding
                    .commitment
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(Error::Configuration);
            }
            let rows = tx
                .query(KEY_GET, params![binding.domain.as_str()])
                .await
                .map_err(|_| Error::Storage)?;
            if let Some(row) = rows.first() {
                if row.get_str(0).map_err(|_| Error::Storage)? != scope
                    || row.get_str(1).map_err(|_| Error::Storage)? != binding.commitment
                {
                    return Err(Error::Configuration);
                }
                continue;
            }
            let gate = binding.domain.gate();
            if !tx
                .query(
                    LEGACY_FINGERPRINT,
                    params!["fingerprint", format!("{gate}:"), format!("{gate};")],
                )
                .await
                .map_err(|_| Error::Storage)?
                .is_empty()
                || !tx
                    .query(
                        LEGACY_ACCOUNT,
                        params!["account", format!("$.gates.{gate}")],
                    )
                    .await
                    .map_err(|_| Error::Storage)?
                    .is_empty()
            {
                return Err(Error::Migration);
            }
            tx.execute(
                KEY_INSERT,
                params![binding.domain.as_str(), scope, binding.commitment.clone()],
            )
            .await
            .map_err(|_| Error::Storage)?;
        }
        tx.commit().await.map_err(|_| Error::Storage)
    }
    fn current(&self, floor: u64, deadline: u64) -> Result<u64> {
        let now = self.clock.now();
        if now < floor || now >= deadline {
            return Err(Error::Expired);
        }
        Ok(now)
    }
    pub async fn reserve(&self, reservation: Reservation) -> Result<Seal> {
        let budget = reservation.budget.domain()?;
        let maximum = &reservation.maximum;
        if reservation.binding.is_empty()
            || reservation.binding.len() > 256
            || maximum.unit != budget.unit
            || maximum.atoms > budget.atoms
            || reservation.max_attempts == 0
            || reservation.dispatch_deadline > reservation.ceremony_deadline
        {
            return Err(Error::Budget);
        }
        let attempts = i64::try_from(reservation.max_attempts).map_err(|_| Error::Budget)?;
        let deadline = i64::try_from(reservation.ceremony_deadline).map_err(|_| Error::Expired)?;
        let dispatch_deadline =
            i64::try_from(reservation.dispatch_deadline).map_err(|_| Error::Expired)?;
        let maximum = i64::try_from(maximum.atoms).map_err(|_| Error::Budget)?;
        let mut floor = self.current(0, reservation.dispatch_deadline)?;
        let mut tx = self.db.tx().await.map_err(|_| Error::Storage)?;
        floor = self.current(floor, reservation.dispatch_deadline)?;
        if !tx
            .query(USED, params![reservation.operation.to_vec()])
            .await
            .map_err(|_| Error::Storage)?
            .is_empty()
        {
            return Err(Error::Conflict);
        }
        floor = self.current(floor, reservation.dispatch_deadline)?;
        let rows = tx
            .query(GET, params![reservation.ceremony.to_vec()])
            .await
            .map_err(|_| Error::Storage)?;
        if let Some(row) = rows.first() {
            if row.get_str(0).map_err(|_| Error::Storage)? != budget.unit.code
                || row.get_i64(1).map_err(|_| Error::Storage)? != i64::from(budget.unit.scale)
                || row.get_i64(2).map_err(|_| Error::Storage)? != budget.atoms as i64
                || row.get_i64(5).map_err(|_| Error::Storage)? != attempts
                || row.get_i64(6).map_err(|_| Error::Storage)? != deadline
            {
                return Err(Error::Conflict);
            }
        } else {
            tx.execute(
                CREATE,
                params![
                    reservation.ceremony.to_vec(),
                    budget.unit.code.clone(),
                    i64::from(budget.unit.scale),
                    budget.atoms as i64,
                    attempts,
                    deadline
                ],
            )
            .await
            .map_err(|_| Error::Storage)?;
        }
        floor = self.current(floor, reservation.dispatch_deadline)?;
        if tx
            .execute(INCREASE, params![maximum, reservation.ceremony.to_vec()])
            .await
            .map_err(|_| Error::Storage)?
            != 1
        {
            return Err(Error::Budget);
        }
        floor = self.current(floor, reservation.dispatch_deadline)?;
        tx.execute(
            DISPATCH,
            params![
                reservation.operation.to_vec(),
                reservation.ceremony.to_vec(),
                reservation.binding.clone(),
                maximum,
                dispatch_deadline
            ],
        )
        .await
        .map_err(|_| Error::Storage)?;
        floor = self.current(floor, reservation.dispatch_deadline)?;
        // Database commit is awaited. Fresh checks here and at the transport
        // suppress late I/O; they do not claim an engine-atomic clock predicate.
        tx.commit().await.map_err(|_| Error::Uncertain)?;
        let now = self
            .current(floor, reservation.dispatch_deadline)
            .map_err(|_| Error::Uncertain)?;
        Ok(Seal {
            reservation,
            clock: self.clock.clone(),
            floor: now,
            consumed: AtomicBool::new(false),
        })
    }
    /// Report an observed outcome without reclaiming unknown or failed fees.
    /// Cancellation before this call leaves the durable default `uncertain`.
    pub async fn complete(
        &self,
        ceremony: &[u8; 32],
        operation: &[u8; 32],
        outcome: Outcome,
    ) -> Result<()> {
        if self
            .db
            .execute(
                COMPLETE,
                params![outcome.as_str(), operation.to_vec(), ceremony.to_vec()],
            )
            .await
            .map_err(|_| Error::Storage)?
            != 1
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub async fn exposure(&self, ceremony: &[u8; 32]) -> Result<Amount> {
        let rows = self
            .db
            .query(GET, params![ceremony.to_vec()])
            .await
            .map_err(|_| Error::Storage)?;
        let row = rows.first().ok_or(Error::Conflict)?;
        Ok(Amount {
            unit: row.get_str(0).map_err(|_| Error::Storage)?.into(),
            scale: row
                .get_i64(1)
                .map_err(|_| Error::Storage)?
                .try_into()
                .map_err(|_| Error::Storage)?,
            atoms: row
                .get_i64(3)
                .map_err(|_| Error::Storage)?
                .try_into()
                .map_err(|_| Error::Storage)?,
        })
    }
    pub async fn check_query_plans(&self) -> Result<()> {
        use crlt::Value;
        let blob = || Value::Blob(vec![0; 32]);
        for (sql, args) in [
            (GET, vec![blob()]),
            (USED, vec![blob()]),
            (
                CREATE,
                vec![
                    blob(),
                    "FIXTURE".into(),
                    0i64.into(),
                    10i64.into(),
                    3i64.into(),
                    200i64.into(),
                ],
            ),
            (INCREASE, vec![1i64.into(), blob()]),
            (
                DISPATCH,
                vec![blob(), blob(), "opaque".into(), 1i64.into(), 200i64.into()],
            ),
            (COMPLETE, vec!["pending".into(), blob(), blob()]),
            (KEY_GET, vec!["cphn.identity.v1:phone.e164".into()]),
            (
                KEY_INSERT,
                vec![
                    "cphn.identity.v1:phone.e164".into(),
                    "global".into(),
                    "0".repeat(64).into(),
                ],
            ),
            (
                LEGACY_FINGERPRINT,
                vec!["fingerprint".into(), "cphn:".into(), "cphn;".into()],
            ),
            (
                LEGACY_ACCOUNT,
                vec!["account".into(), "$.gates.cphn".into()],
            ),
        ] {
            self.db
                .explain(sql, args)
                .await
                .map_err(|_| Error::Storage)?
                .assert_indexed()
                .map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
}

/// Only an already committed reservation can construct this synchronous bridge.
/// It is move-only and verifies the leaf's exact terms once with a fresh clock.
pub struct Seal {
    reservation: Reservation,
    clock: Arc<dyn Clock>,
    floor: u64,
    consumed: AtomicBool,
}
impl Seal {
    pub(crate) fn retain_authorization_floor(&mut self, authorized_at: u64) -> Result<()> {
        let now = self.clock.now();
        if authorized_at < self.floor
            || now < authorized_at
            || now >= self.reservation.dispatch_deadline
        {
            return Err(Error::Uncertain);
        }
        self.floor = now;
        Ok(())
    }
    fn consume(
        &self,
        ceremony: &[u8; 32],
        operation: &[u8; 32],
        binding: &str,
        maximum: &cost::Amount,
        deadline: u64,
    ) -> bool {
        let now = self.clock.now();
        ceremony == &self.reservation.leaf_binding
            && operation == &self.reservation.operation
            && binding == self.reservation.binding
            && maximum == &self.reservation.maximum
            && deadline == self.reservation.dispatch_deadline
            && now >= self.floor
            && now < deadline
            && self
                .consumed
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
    }
}
impl cphn::DispatchState for Seal {
    fn reserve(
        &self,
        ceremony: &[u8; 32],
        operation: &[u8; 32],
        binding: &str,
        maximum: &cost::Amount,
        deadline: u64,
    ) -> std::result::Result<(), cphn::Error> {
        if self.consume(ceremony, operation, binding, maximum, deadline) {
            Ok(())
        } else {
            Err(cphn::Error::Reservation)
        }
    }
}
impl cmbx::DispatchState for Seal {
    fn reserve(
        &self,
        ceremony: &[u8; 32],
        operation: &[u8; 32],
        binding: &str,
        maximum: &cost::Amount,
        deadline: u64,
    ) -> std::result::Result<(), cmbx::Error> {
        if self.consume(ceremony, operation, binding, maximum, deadline) {
            Ok(())
        } else {
            Err(cmbx::Error::Reservation)
        }
    }
}
