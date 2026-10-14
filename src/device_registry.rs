//! Per-community registry of a member's device keys. A key is `pending`, `active` or
//! `revoked`; only an active key can open a device session. Changes arrive only through
//! stamped actions (a later package); the one non-stamped entry is the first key bound at
//! join, see [`bind_first_device_key`].
use crate::error::{Error, Result};
use crlt::{Db, params};

pub const SCHEMA: &str = "CREATE TABLE cvld_device_registry (
    community_id TEXT NOT NULL,
    member TEXT NOT NULL CHECK (length(member) BETWEEN 1 AND 64),
    device_key BLOB NOT NULL CHECK (length(device_key) = 32),
    state TEXT NOT NULL CHECK (state IN ('pending','active','revoked')),
    PRIMARY KEY (community_id, member, device_key)
) WITHOUT ROWID;";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Pending,
    Active,
    Revoked,
}
impl State {
    #[cfg(test)]
    fn name(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Active => "active",
            State::Revoked => "revoked",
        }
    }
}

/// JOIN HOOK. Called once the existing authenticated join has proved the member (today the
/// passkey session calling `device_authorize`). The first key of a member becomes active;
/// any later call for a member that already has a key changes nothing. Package 5 replaces the
/// caller's authority with the passport presentation plus one stamp.
pub async fn bind_first_device_key(
    db: &Db,
    scope: &str,
    member: &str,
    device_key: &[u8; 32],
) -> Result<()> {
    let mut tx = db.tx(scope).await.map_err(Error::Unavailable.redact())?;
    let rows = tx
        .query(
            "SELECT 1 FROM cvld_device_registry WHERE member = ?1",
            params![member.to_owned()],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    if !rows.is_empty() {
        return tx.rollback().await.map_err(Error::Unavailable.redact());
    }
    tx.execute(
        "INSERT INTO cvld_device_registry (member, device_key, state) VALUES (?1, ?2, 'active')",
        params![member.to_owned(), device_key.to_vec()],
    )
    .await
    .map_err(Error::Unavailable.redact())?;
    tx.commit().await.map_err(Error::Unavailable.redact())
}

/// The registered state of this member's key in this community; `None` when unknown.
pub async fn state(
    db: &Db,
    scope: &str,
    member: &str,
    device_key: &[u8; 32],
) -> Result<Option<State>> {
    let rows = db
        .community(scope)
        .map_err(Error::Invalid.redact())?
        .query(
            "SELECT state FROM cvld_device_registry WHERE member = ?1 AND device_key = ?2",
            params![member.to_owned(), device_key.to_vec()],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    match row.get_value(0).map_err(Error::Unavailable.redact())? {
        crlt::Value::Text(text) => match text.as_str() {
            "pending" => Ok(Some(State::Pending)),
            "active" => Ok(Some(State::Active)),
            "revoked" => Ok(Some(State::Revoked)),
            _ => Err(Error::Unavailable),
        },
        _ => Err(Error::Unavailable),
    }
}

/// Test fixture for the states a stamped action will later write.
#[cfg(test)]
pub async fn put(
    db: &Db,
    scope: &str,
    member: &str,
    device_key: &[u8; 32],
    state: State,
) -> Result<()> {
    let mut tx = db.tx(scope).await.map_err(Error::Unavailable.redact())?;
    tx.execute(
        "DELETE FROM cvld_device_registry WHERE member = ?1 AND device_key = ?2",
        params![member.to_owned(), device_key.to_vec()],
    )
    .await
    .map_err(Error::Unavailable.redact())?;
    tx.execute(
        "INSERT INTO cvld_device_registry (member, device_key, state) VALUES (?1, ?2, ?3)",
        params![
            member.to_owned(),
            device_key.to_vec(),
            state.name().to_owned()
        ],
    )
    .await
    .map_err(Error::Unavailable.redact())?;
    tx.commit().await.map_err(Error::Unavailable.redact())
}
