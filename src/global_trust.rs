//! Public trust anchors and durable rollback floors; never global member data.
use crate::{
    config::CommunityConfig,
    error::{Error, Result},
};
use crlt::{Db, params};

pub const SCHEMA: &str = "CREATE TABLE cvld_global_trust (
    community_id TEXT PRIMARY KEY NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    revision INTEGER NOT NULL CHECK (revision > 0)
) WITHOUT ROWID;";

pub struct PublicStatus {
    pub status: cgbl::Status,
    pub valid_until: u64,
    pub signing_keys: Vec<[u8; 32]>,
}

pub async fn load(db: &Db, config: &CommunityConfig, now: u64) -> Result<PublicStatus> {
    let mut tx = db
        .tx(&config.community)
        .await
        .map_err(Error::Unavailable.redact())?;
    let rows = tx
        .query("SELECT epoch, revision FROM cvld_global_trust", ())
        .await
        .map_err(Error::Unavailable.redact())?;
    let mut epoch = config.minimum_global_epoch;
    let mut revision = config.minimum_global_revision;
    if let Some(row) = rows.first() {
        epoch = epoch.max(
            row.get_i64(0)
                .map_err(Error::Unavailable.redact())?
                .try_into()
                .map_err(Error::Unavailable.redact())?,
        );
        revision = revision.max(
            row.get_i64(1)
                .map_err(Error::Unavailable.redact())?
                .try_into()
                .map_err(Error::Unavailable.redact())?,
        );
    }
    let ring = csgn::KeyRing::from_cbor(
        &std::fs::read(&config.global_key_ring_file).map_err(Error::Unavailable.redact())?,
    )
    .map_err(Error::Invalid.redact())?;
    let signed = std::fs::read(&config.global_status_file).map_err(Error::Unavailable.redact())?;
    let status = cgbl::Status::verify(&signed, &ring, "global", epoch, revision, now)
        .map_err(Error::Refused.redact())?;
    let valid_until = ring
        .verify(&signed, csgn::Kind::SettingsSnapshot, now)
        .map_err(Error::Refused.redact())?
        .valid_until();
    let epoch: i64 = status.epoch.try_into().map_err(Error::Invalid.redact())?;
    let revision: i64 = status
        .policy_revision
        .try_into()
        .map_err(Error::Invalid.redact())?;
    if rows.is_empty() {
        tx.execute(
            "INSERT INTO cvld_global_trust (epoch, revision) VALUES (?1, ?2)",
            params![epoch, revision],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    } else {
        tx.execute(
            "UPDATE cvld_global_trust SET epoch = ?1, revision = ?2",
            params![epoch, revision],
        )
        .await
        .map_err(Error::Unavailable.redact())?;
    }
    tx.commit().await.map_err(Error::Unavailable.redact())?;
    Ok(PublicStatus {
        status,
        valid_until,
        signing_keys: ring.keys().iter().map(csgn::KeyEntry::public_key).collect(),
    })
}
