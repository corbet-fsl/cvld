//! Community registry: which communities exist, under which address and founding
//! fingerprint, and in which life-cycle state. It lives in the GLOBAL scope of the
//! shared database; each community's own data is a separate scope keyed by its
//! address while it lives. The registry serves no keys: keys come from each
//! community's signed feed, verified against the fingerprint recorded here.
use crate::{
    address::{self, Reserved},
    error::{Error, Result},
};
use crlt::{Community, Value, params};

pub const SCHEMA: &str = "CREATE TABLE cvld_communities (
    community_id TEXT NOT NULL,
    id BLOB NOT NULL CHECK (length(id) = 16),
    address TEXT NOT NULL CHECK (length(address) BETWEEN 8 AND 30 AND NOT address GLOB '*[^a-z0-9]*'),
    fingerprint BLOB CHECK (fingerprint IS NULL OR length(fingerprint) = 32),
    claim_hash BLOB NOT NULL CHECK (length(claim_hash) = 32),
    state TEXT NOT NULL CHECK (state IN ('being_created', 'live', 'ending', 'ended')),
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    ended_at INTEGER,
    hold_until INTEGER,
    end_reason TEXT CHECK (end_reason IS NULL OR end_reason IN ('legal', 'terms', 'name', 'dissolved')),
    seq INTEGER NOT NULL,
    PRIMARY KEY (community_id, id)
) WITHOUT ROWID;
CREATE INDEX cvld_communities_address ON cvld_communities (community_id, address);
CREATE INDEX cvld_communities_seq ON cvld_communities (community_id, seq);
CREATE TABLE cvld_blocked_names (
    community_id TEXT NOT NULL,
    address TEXT NOT NULL,
    PRIMARY KEY (community_id, address)
) WITHOUT ROWID;";

/// Later registry migration: the sealed data of communities under a legal hold.
/// Migration history is immutable, so this is a separate migration.
pub const HELD_SCHEMA: &str = "CREATE TABLE cvld_held (
    community_id TEXT NOT NULL,
    id BLOB NOT NULL CHECK (length(id) = 16),
    hold_until INTEGER NOT NULL,
    sealed BLOB NOT NULL,
    PRIMARY KEY (community_id, id)
) WITHOUT ROWID;";

/// Life-cycle state of a registered community.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Shell: registered, not yet admitting its creator. Expires if abandoned.
    BeingCreated,
    Live,
    /// Refuses everything; data deletion pending or retained under a hold.
    Ending,
    Ended,
}

impl State {
    pub fn code(self) -> &'static str {
        match self {
            Self::BeingCreated => "being_created",
            Self::Live => "live",
            Self::Ending => "ending",
            Self::Ended => "ended",
        }
    }
    fn parse(code: &str) -> Result<Self> {
        match code {
            "being_created" => Ok(Self::BeingCreated),
            "live" => Ok(Self::Live),
            "ending" => Ok(Self::Ending),
            "ended" => Ok(Self::Ended),
            _ => Err(Error::Unavailable),
        }
    }
    /// A state in which the community's hostnames resolve to it.
    pub fn serves(self) -> bool {
        matches!(self, Self::BeingCreated | Self::Live)
    }
}

/// One registered community incarnation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: [u8; 16],
    pub address: String,
    /// Set once the community's genesis document exists.
    pub fingerprint: Option<[u8; 32]>,
    pub state: State,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub ended_at: Option<u64>,
    pub hold_until: Option<u64>,
    /// Why the community ended: legal, terms, name or dissolved (by its admins).
    pub end_reason: Option<String>,
    /// Change counter used as the cursor of the finished-communities listing.
    pub seq: u64,
    pub claim_hash: [u8; 32],
}

/// Which of a community's two hostnames was matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Community,
    Vault,
}

pub struct Registry {
    scope: Community,
}

fn db<T>(_: T) -> Error {
    Error::Unavailable
}

fn blob<const N: usize>(row: &crlt::Row, index: usize) -> Result<[u8; N]> {
    match row.get_value(index).map_err(db)? {
        Value::Blob(bytes) => bytes.as_slice().try_into().map_err(db),
        _ => Err(Error::Unavailable),
    }
}

fn optional(row: &crlt::Row, index: usize) -> Result<Option<u64>> {
    match row.get_value(index).map_err(db)? {
        Value::Null => Ok(None),
        Value::Integer(value) => u64::try_from(*value).map(Some).map_err(db),
        _ => Err(Error::Unavailable),
    }
}

const COLUMNS: &str = "id, address, fingerprint, state, created_at, expires_at, ended_at, hold_until, seq, claim_hash, end_reason";

fn entry(row: &crlt::Row) -> Result<Entry> {
    Ok(Entry {
        id: blob(row, 0)?,
        address: row.get_str(1).map_err(db)?.to_owned(),
        fingerprint: match row.get_value(2).map_err(db)? {
            Value::Null => None,
            _ => Some(blob(row, 2)?),
        },
        state: State::parse(row.get_str(3).map_err(db)?)?,
        created_at: u64::try_from(row.get_i64(4).map_err(db)?).map_err(db)?,
        expires_at: optional(row, 5)?,
        ended_at: optional(row, 6)?,
        hold_until: optional(row, 7)?,
        seq: u64::try_from(row.get_i64(8).map_err(db)?).map_err(db)?,
        claim_hash: blob(row, 9)?,
        end_reason: match row.get_value(10).map_err(db)? {
            Value::Text(reason) => Some(reason.clone()),
            _ => None,
        },
    })
}

fn int(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Invalid)
}

impl Registry {
    /// `scope` must be the global scope of the shared database, already migrated.
    pub fn new(scope: Community) -> Self {
        Self { scope }
    }

    /// Register a shell for a new incarnation. The address must be valid, not
    /// reserved, not blocked and not held by a live, ending or held community.
    pub async fn create_shell(
        &self,
        id: [u8; 16],
        address: &str,
        claim_hash: [u8; 32],
        now: u64,
        shell_seconds: u64,
        reserved: &Reserved,
    ) -> Result<Entry> {
        address::validate(address, reserved).map_err(|_| Error::Invalid)?;
        let mut tx = self.scope.tx().await.map_err(db)?;
        let blocked = tx
            .query(
                "SELECT address FROM cvld_blocked_names WHERE address = ?1",
                [address],
            )
            .await
            .map_err(db)?;
        let taken = tx
            .query(
                "SELECT state, hold_until FROM cvld_communities WHERE address = ?1",
                [address],
            )
            .await
            .map_err(db)?;
        let occupied = taken.iter().try_fold(false, |busy, row| -> Result<bool> {
            let state = State::parse(row.get_str(0).map_err(db)?)?;
            let held = optional(row, 1)?.is_some_and(|until| until > now);
            Ok(busy || state != State::Ended || held)
        })?;
        if !blocked.is_empty() || occupied {
            tx.rollback().await.map_err(db)?;
            return Err(Error::Refused);
        }
        let seq = next_seq(&mut tx).await?;
        let expires_at = now.checked_add(shell_seconds).ok_or(Error::Invalid)?;
        tx.execute(
            "INSERT INTO cvld_communities (id, address, claim_hash, state, created_at, expires_at, seq) VALUES (?1, ?2, ?3, 'being_created', ?4, ?5, ?6)",
            params![id.to_vec(), address, claim_hash.to_vec(), int(now)?, int(expires_at)?, int(seq)?],
        )
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(Entry {
            id,
            address: address.to_owned(),
            fingerprint: None,
            claim_hash,
            state: State::BeingCreated,
            created_at: now,
            expires_at: Some(expires_at),
            ended_at: None,
            hold_until: None,
            end_reason: None,
            seq,
        })
    }

    /// Record the founding fingerprint of a shell once its genesis exists.
    pub async fn set_fingerprint(&self, id: [u8; 16], fingerprint: [u8; 32]) -> Result<()> {
        let mut tx = self.scope.tx().await.map_err(db)?;
        let changed = tx
            .execute(
                "UPDATE cvld_communities SET fingerprint = ?2 WHERE id = ?1 AND state = 'being_created' AND fingerprint IS NULL",
                params![id.to_vec(), fingerprint.to_vec()],
            )
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(Error::Refused)
        }
    }

    /// Shell to live: the creator is admitted and the token is spent.
    pub async fn mark_live(&self, id: [u8; 16]) -> Result<()> {
        self.transition(id, State::BeingCreated, State::Live)
            .await
            .map(|_| ())
    }

    /// Keep a shell alive until `until`: the creator is still on its way (resumed
    /// creation or a claimed seat waiting for the admission).
    pub async fn extend_shell(&self, id: [u8; 16], until: u64) -> Result<()> {
        let mut tx = self.scope.tx().await.map_err(db)?;
        tx.execute(
            "UPDATE cvld_communities SET expires_at = ?2 WHERE id = ?1 AND state = 'being_created' AND (expires_at IS NULL OR expires_at < ?2)",
            params![id.to_vec(), int(until)?],
        )
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)
    }

    /// Remove a shell that was never completed (rollback or expiry).
    pub async fn remove_shell(&self, id: [u8; 16]) -> Result<()> {
        let mut tx = self.scope.tx().await.map_err(db)?;
        let removed = tx
            .execute(
                "DELETE FROM cvld_communities WHERE id = ?1 AND state = 'being_created'",
                [id.to_vec()],
            )
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        if removed == 1 {
            Ok(())
        } else {
            Err(Error::Refused)
        }
    }

    /// Live (or abandoned shell) to ending: from now on nothing is served.
    /// Returns the change counter. `hold_until` retains the address until then.
    pub async fn begin_end(
        &self,
        id: [u8; 16],
        now: u64,
        reason: &str,
        hold_until: Option<u64>,
        block_name: bool,
    ) -> Result<Entry> {
        let mut tx = self.scope.tx().await.map_err(db)?;
        let rows = tx
            .query(
                &format!("SELECT {COLUMNS} FROM cvld_communities WHERE id = ?1"),
                [id.to_vec()],
            )
            .await
            .map_err(db)?;
        let current = rows.first().map(entry).transpose()?.ok_or(Error::Refused)?;
        if !matches!(current.state, State::Live | State::BeingCreated) {
            tx.rollback().await.map_err(db)?;
            return Err(Error::Refused);
        }
        let seq = next_seq(&mut tx).await?;
        tx.execute(
            "UPDATE cvld_communities SET state = 'ending', ended_at = ?2, hold_until = ?3, end_reason = ?5, seq = ?4 WHERE id = ?1",
            params![
                id.to_vec(),
                int(now)?,
                hold_until.map(int).transpose()?,
                int(seq)?,
                reason
            ],
        )
        .await
        .map_err(db)?;
        if block_name {
            let known = tx
                .query(
                    "SELECT address FROM cvld_blocked_names WHERE address = ?1",
                    [current.address.as_str()],
                )
                .await
                .map_err(db)?;
            if known.is_empty() {
                tx.execute(
                    "INSERT INTO cvld_blocked_names (address) VALUES (?1)",
                    [current.address.as_str()],
                )
                .await
                .map_err(db)?;
            }
        }
        tx.commit().await.map_err(db)?;
        Ok(Entry {
            state: State::Ending,
            ended_at: Some(now),
            hold_until,
            end_reason: Some(reason.to_owned()),
            seq,
            ..current
        })
    }

    /// Keep the sealed data of a community under a legal hold until `until`.
    pub async fn store_held(&self, id: [u8; 16], until: u64, sealed: &[u8]) -> Result<()> {
        let mut tx = self.scope.tx().await.map_err(db)?;
        tx.execute("DELETE FROM cvld_held WHERE id = ?1", [id.to_vec()])
            .await
            .map_err(db)?;
        tx.execute(
            "INSERT INTO cvld_held (id, hold_until, sealed) VALUES (?1, ?2, ?3)",
            params![id.to_vec(), int(until)?, sealed.to_vec()],
        )
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)
    }

    /// The sealed data kept for a community under a legal hold.
    pub async fn held(&self, id: [u8; 16]) -> Result<Option<Vec<u8>>> {
        let rows = self
            .scope
            .query("SELECT sealed FROM cvld_held WHERE id = ?1", [id.to_vec()])
            .await
            .map_err(db)?;
        match rows.first() {
            None => Ok(None),
            Some(row) => match row.get_value(0).map_err(db)? {
                Value::Blob(bytes) => Ok(Some(bytes.clone())),
                _ => Err(Error::Unavailable),
            },
        }
    }

    /// Delete the held data (the hold ended).
    pub async fn delete_held(&self, id: [u8; 16]) -> Result<()> {
        let mut tx = self.scope.tx().await.map_err(db)?;
        tx.execute("DELETE FROM cvld_held WHERE id = ?1", [id.to_vec()])
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)
    }

    /// Communities in `ending` under a hold that has not passed yet.
    pub async fn holding(&self, now: u64) -> Result<Vec<Entry>> {
        let rows = self
            .scope
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM cvld_communities WHERE state = 'ending' AND hold_until > ?1"
                ),
                [int(now)?],
            )
            .await
            .map_err(db)?;
        rows.iter().map(entry).collect()
    }

    /// Ending to ended: the community's data is gone (or was deleted at hold end).
    pub async fn finish_end(&self, id: [u8; 16]) -> Result<()> {
        self.transition(id, State::Ending, State::Ended)
            .await
            .map(|_| ())
    }

    async fn transition(&self, id: [u8; 16], from: State, to: State) -> Result<u64> {
        let mut tx = self.scope.tx().await.map_err(db)?;
        let seq = next_seq(&mut tx).await?;
        let changed = tx
            .execute(
                "UPDATE cvld_communities SET state = ?2, expires_at = NULL, seq = ?4 WHERE id = ?1 AND state = ?3",
                params![id.to_vec(), to.code(), from.code(), int(seq)?],
            )
            .await
            .map_err(db)?;
        if changed != 1 {
            tx.rollback().await.map_err(db)?;
            return Err(Error::Refused);
        }
        tx.commit().await.map_err(db)?;
        Ok(seq)
    }

    /// The community currently or still holding this address, if any.
    pub async fn by_address(&self, address: &str, now: u64) -> Result<Option<Entry>> {
        let rows = self
            .scope
            .query(
                &format!("SELECT {COLUMNS} FROM cvld_communities WHERE address = ?1"),
                [address],
            )
            .await
            .map_err(db)?;
        let mut found = None;
        for row in &rows {
            let item = entry(row)?;
            let held = item.hold_until.is_some_and(|until| until > now);
            if item.state != State::Ended || held {
                found = Some(item);
            }
        }
        Ok(found)
    }

    pub async fn by_id(&self, id: [u8; 16]) -> Result<Option<Entry>> {
        let rows = self
            .scope
            .query(
                &format!("SELECT {COLUMNS} FROM cvld_communities WHERE id = ?1"),
                [id.to_vec()],
            )
            .await
            .map_err(db)?;
        rows.first().map(entry).transpose()
    }

    /// Resolve `<address>.<base>` or `vault.<address>.<base>`. Only serving
    /// states resolve; ended, ending and unknown hosts return `None`.
    pub async fn by_host(&self, host: &str, base: &str) -> Result<Option<(Entry, Origin)>> {
        let Some(label) = host
            .strip_suffix(base)
            .and_then(|rest| rest.strip_suffix('.'))
        else {
            return Ok(None);
        };
        let (address, origin) = match label.strip_prefix("vault.") {
            Some(address) => (address, Origin::Vault),
            None => (label, Origin::Community),
        };
        if address::check_syntax(address).is_err() {
            return Ok(None);
        }
        Ok(self
            .by_address(address, 0)
            .await?
            .filter(|item| item.state.serves())
            .map(|item| (item, origin)))
    }

    /// Ending and ended communities with a change counter above `cursor`.
    pub async fn finished_since(&self, cursor: u64, limit: usize) -> Result<Vec<Entry>> {
        let rows = self
            .scope
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM cvld_communities WHERE seq > ?1 ORDER BY seq LIMIT ?2"
                ),
                params![int(cursor)?, int(limit as u64)?],
            )
            .await
            .map_err(db)?;
        let mut out = Vec::new();
        for row in &rows {
            let item = entry(row)?;
            if !item.state.serves() {
                out.push(item);
            }
        }
        Ok(out)
    }

    /// Communities in `ending` whose hold (if any) has passed.
    pub async fn due_for_deletion(&self, now: u64) -> Result<Vec<Entry>> {
        let rows = self
            .scope
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM cvld_communities WHERE state = 'ending' AND (hold_until IS NULL OR hold_until <= ?1)"
                ),
                [int(now)?],
            )
            .await
            .map_err(db)?;
        rows.iter().map(entry).collect()
    }

    /// Every community whose hostnames resolve (shells and live ones).
    pub async fn serving(&self) -> Result<Vec<Entry>> {
        let rows = self
            .scope
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM cvld_communities WHERE state = 'live' OR state = 'being_created'"
                ),
                (),
            )
            .await
            .map_err(db)?;
        rows.iter().map(entry).collect()
    }

    /// Abandoned shells whose expiry passed.
    pub async fn expired_shells(&self, now: u64) -> Result<Vec<Entry>> {
        let rows = self
            .scope
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM cvld_communities WHERE state = 'being_created' AND expires_at <= ?1"
                ),
                [int(now)?],
            )
            .await
            .map_err(db)?;
        rows.iter().map(entry).collect()
    }
}

async fn next_seq(tx: &mut crlt::Transaction) -> Result<u64> {
    let rows = tx
        .query("SELECT COALESCE(MAX(seq), 0) FROM cvld_communities", ())
        .await
        .map_err(db)?;
    let last = rows
        .first()
        .ok_or(Error::Unavailable)?
        .get_i64(0)
        .map_err(db)?;
    u64::try_from(last + 1).map_err(db)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn registry() -> (tempfile::TempDir, Registry) {
        let dir = tempfile::tempdir().unwrap();
        let config = crlt::Config::new(format!("file://{}", dir.path().join("r.db").display()), "");
        let db = crlt::Db::open(config).await.unwrap();
        db.migrate(&[crlt::Migration::new(1, "registry", SCHEMA)])
            .await
            .unwrap();
        (dir, Registry::new(db.community("global").unwrap()))
    }

    const BASE: &str = "cmtymeet.corbet.ch";
    const FP: [u8; 32] = [7; 32]; // claim hash in these tests

    #[tokio::test]
    async fn shell_live_end_and_reuse() {
        let (_dir, registry) = registry().await;
        let none = Reserved::default();
        let one = [1; 16];
        registry
            .create_shell(one, "gardenclub", FP, 100, 600, &none)
            .await
            .unwrap();
        // A live or being-created address is taken.
        assert_eq!(
            registry
                .create_shell([2; 16], "gardenclub", FP, 101, 600, &none)
                .await,
            Err(Error::Refused)
        );
        let (item, origin) = registry
            .by_host("gardenclub.cmtymeet.corbet.ch", BASE)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((item.id, origin), (one, Origin::Community));
        let (_, vault) = registry
            .by_host("vault.gardenclub.cmtymeet.corbet.ch", BASE)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(vault, Origin::Vault);
        registry.mark_live(one).await.unwrap();
        assert_eq!(registry.mark_live(one).await, Err(Error::Refused));
        let ending = registry
            .begin_end(one, 200, "dissolved", None, false)
            .await
            .unwrap();
        assert_eq!(ending.state, State::Ending);
        assert!(
            registry
                .by_host("gardenclub.cmtymeet.corbet.ch", BASE)
                .await
                .unwrap()
                .is_none()
        );
        registry.finish_end(one).await.unwrap();
        let finished = registry.finished_since(0, 10).await.unwrap();
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0].state, State::Ended);
        assert_eq!(
            registry.finished_since(finished[0].seq, 10).await.unwrap(),
            []
        );
        // Reusable at once, as a new incarnation with a new id.
        registry
            .create_shell([3; 16], "gardenclub", [8; 32], 300, 600, &none)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn hold_and_block_keep_the_address_unavailable() {
        let (_dir, registry) = registry().await;
        let none = Reserved::default();
        registry
            .create_shell([1; 16], "heldname1", FP, 100, 600, &none)
            .await
            .unwrap();
        registry.mark_live([1; 16]).await.unwrap();
        registry
            .begin_end([1; 16], 200, "legal", Some(1000), false)
            .await
            .unwrap();
        registry.finish_end([1; 16]).await.unwrap();
        assert_eq!(
            registry
                .create_shell([2; 16], "heldname1", FP, 500, 600, &none)
                .await,
            Err(Error::Refused)
        );
        registry
            .create_shell([2; 16], "heldname1", FP, 1000, 600, &none)
            .await
            .unwrap();
        registry
            .create_shell([3; 16], "blockedone", FP, 100, 600, &none)
            .await
            .unwrap();
        registry.mark_live([3; 16]).await.unwrap();
        registry
            .begin_end([3; 16], 200, "name", None, true)
            .await
            .unwrap();
        registry.finish_end([3; 16]).await.unwrap();
        assert_eq!(
            registry
                .create_shell([4; 16], "blockedone", FP, 9000, 600, &none)
                .await,
            Err(Error::Refused)
        );
    }

    #[tokio::test]
    async fn invalid_and_reserved_addresses_and_abandoned_shells() {
        let (_dir, registry) = registry().await;
        let reserved = Reserved::new(["walletwall"]);
        for bad in ["short", "has-hyphen", "walletwall"] {
            assert_eq!(
                registry
                    .create_shell([9; 16], bad, FP, 100, 600, &reserved)
                    .await,
                Err(Error::Invalid)
            );
        }
        registry
            .create_shell([5; 16], "abandoned1", FP, 100, 600, &reserved)
            .await
            .unwrap();
        assert!(registry.expired_shells(699).await.unwrap().is_empty());
        let expired = registry.expired_shells(700).await.unwrap();
        assert_eq!(expired.len(), 1);
        registry.remove_shell([5; 16]).await.unwrap();
        assert!(
            registry
                .by_address("abandoned1", 700)
                .await
                .unwrap()
                .is_none()
        );
    }
}
