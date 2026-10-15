//! Per-community registry of a member's device keys. The registry, its states and its only
//! writers live in the membership facade (`cmbr`); this module names its migration and keeps
//! the test helpers that write states the stamped actions write in production.
pub const SCHEMA: &str = cmty::cmbr::DEVICE_REGISTRY_SCHEMA;
#[cfg(test)]
pub use cmty::cmbr::DeviceKeyState as State;

#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crlt::{Db, params};

/// Test fixture: set the state of one key directly.
#[cfg(test)]
pub async fn put(
    db: &Db,
    scope: &str,
    member: &str,
    device_key: &[u8; 32],
    state: State,
) -> Result<()> {
    let name = match state {
        State::Pending => "pending",
        State::Active => "active",
        State::Revoked => "revoked",
    };
    let mut tx = db.tx(scope).await.map_err(Error::Unavailable.redact())?;
    tx.execute(
        "DELETE FROM cvld_device_registry WHERE member = ?1 AND device_key = ?2",
        params![member.to_owned(), device_key.to_vec()],
    )
    .await
    .map_err(Error::Unavailable.redact())?;
    tx.execute(
        "INSERT INTO cvld_device_registry (member, device_key, state) VALUES (?1, ?2, ?3)",
        params![member.to_owned(), device_key.to_vec(), name.to_owned()],
    )
    .await
    .map_err(Error::Unavailable.redact())?;
    tx.commit().await.map_err(Error::Unavailable.redact())
}

/// Test fixture: the registered state of one key.
#[cfg(test)]
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
        crlt::Value::Text(text) if text == "pending" => Ok(Some(State::Pending)),
        crlt::Value::Text(text) if text == "active" => Ok(Some(State::Active)),
        crlt::Value::Text(text) if text == "revoked" => Ok(Some(State::Revoked)),
        _ => Err(Error::Unavailable),
    }
}
