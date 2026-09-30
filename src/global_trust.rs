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
    pub status: cglb::Status,
    pub valid_until: u64,
    pub signing_keys: Vec<[u8; 32]>,
}

pub async fn load(db: &Db, config: &CommunityConfig, now: u64) -> Result<PublicStatus> {
    let mut tx = db
        .tx(&config.community)
        .await
        .map_err(|_| Error::Unavailable)?;
    let rows = tx
        .query("SELECT epoch, revision FROM cvld_global_trust", ())
        .await
        .map_err(|_| Error::Unavailable)?;
    let mut epoch = config.minimum_global_epoch;
    let mut revision = config.minimum_global_revision;
    if let Some(row) = rows.first() {
        epoch = epoch.max(
            row.get_i64(0)
                .map_err(|_| Error::Unavailable)?
                .try_into()
                .map_err(|_| Error::Unavailable)?,
        );
        revision = revision.max(
            row.get_i64(1)
                .map_err(|_| Error::Unavailable)?
                .try_into()
                .map_err(|_| Error::Unavailable)?,
        );
    }
    let ring = csgn::KeyRing::from_cbor(
        &std::fs::read(&config.global_key_ring_file).map_err(|_| Error::Unavailable)?,
    )
    .map_err(|_| Error::Invalid)?;
    let signed = std::fs::read(&config.global_status_file).map_err(|_| Error::Unavailable)?;
    let status = cglb::Status::verify(&signed, &ring, "global", epoch, revision, now)
        .map_err(|_| Error::Refused)?;
    let valid_until = ring
        .verify(&signed, csgn::Kind::SettingsSnapshot, now)
        .map_err(|_| Error::Refused)?
        .valid_until();
    let epoch: i64 = status.epoch.try_into().map_err(|_| Error::Invalid)?;
    let revision: i64 = status
        .policy_revision
        .try_into()
        .map_err(|_| Error::Invalid)?;
    if rows.is_empty() {
        tx.execute(
            "INSERT INTO cvld_global_trust (epoch, revision) VALUES (?1, ?2)",
            params![epoch, revision],
        )
        .await
        .map_err(|_| Error::Unavailable)?;
    } else {
        tx.execute(
            "UPDATE cvld_global_trust SET epoch = ?1, revision = ?2",
            params![epoch, revision],
        )
        .await
        .map_err(|_| Error::Unavailable)?;
    }
    tx.commit().await.map_err(|_| Error::Unavailable)?;
    Ok(PublicStatus {
        status,
        valid_until,
        signing_keys: ring.keys().iter().map(csgn::KeyEntry::public_key).collect(),
    })
}
