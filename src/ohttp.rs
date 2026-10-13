//! Oblivious HTTP gateway wiring: keys from secret files, replay table in the
//! door database. Without the `ohttp` feature a configured gateway refuses to
//! start and no request is ever marked as arriving through one.
use crate::config::OhttpConfig;
use crate::error::{Error, Result};

#[cfg(feature = "ohttp")]
pub(crate) type Mounted = std::sync::Arc<cblv::gateway::Gateway>;
#[cfg(not(feature = "ohttp"))]
pub(crate) type Mounted = std::convert::Infallible;

pub(crate) const SCHEMA: &str = "CREATE TABLE cvld_ohttp_replay (
    community_id TEXT NOT NULL,
    id BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (community_id, id)
) WITHOUT ROWID;
CREATE TABLE cvld_ohttp_epoch (
    community_id TEXT NOT NULL PRIMARY KEY,
    started_at INTEGER NOT NULL
) WITHOUT ROWID;";

/// True when the gateway layer unwrapped this request, so its network source is
/// the relay and per-source limits cannot apply to it.
#[cfg(feature = "ohttp")]
pub(crate) fn via(request: &axum::extract::Request) -> bool {
    request
        .extensions()
        .get::<cblv::gateway::ViaOhttp>()
        .is_some()
}
#[cfg(not(feature = "ohttp"))]
pub(crate) fn via(_: &axum::extract::Request) -> bool {
    false
}

/// The hosting hub of a multi-tenant global door, filled once by the launcher.
pub(crate) type HubSlot = std::sync::Arc<std::sync::OnceLock<std::sync::Arc<dyn crate::service::CommunityHub>>>;

/// Authorities the gateway serves: the door's own configured host, plus (global door) every
/// community the hub reports as live. Everything else is refused uniformly.
#[cfg(feature = "ohttp")]
struct Live {
    own: String,
    hub: Option<HubSlot>,
}
#[cfg(feature = "ohttp")]
impl cblv::gateway::Authorities for Live {
    fn accepts<'a>(&'a self, authority: &'a [u8]) -> cblv::replay::BoxFuture<'a, bool> {
        Box::pin(async move {
            let Ok(host) = std::str::from_utf8(authority) else {
                return false;
            };
            if host == self.own {
                return true;
            }
            match self.hub.as_ref().and_then(|slot| slot.get()) {
                Some(hub) => hub.serves_host(host).await,
                None => false,
            }
        })
    }
}

/// Build the gateway for one door, or none when it is not configured.
#[cfg(not(feature = "ohttp"))]
pub(crate) async fn build(
    config: Option<&OhttpConfig>,
    _hosts: &[String],
    _db: &crlt::Db,
    _scope: &str,
    _hub: Option<HubSlot>,
) -> Result<Option<Mounted>> {
    match config {
        None => Ok(None),
        Some(_) => Err(Error::Invalid),
    }
}

#[cfg(feature = "ohttp")]
pub(crate) async fn build(
    config: Option<&OhttpConfig>,
    hosts: &[String],
    db: &crlt::Db,
    scope: &str,
    hub: Option<HubSlot>,
) -> Result<Option<Mounted>> {
    use cblv::gateway::{Gateway, GatewayKey, system_clock};
    let Some(config) = config else {
        return Ok(None);
    };
    if !hosts.contains(&config.authority) || config.keys.is_empty() || config.keys.len() > 4 {
        return Err(Error::Invalid);
    }
    let mut keys = Vec::new();
    for file in &config.keys {
        keys.push(
            GatewayKey::derive(
                file.key_id,
                &crate::config::Config::secret(&file.ikm_file)?,
                file.not_after,
            )
            .map_err(Error::Invalid.redact())?,
        );
    }
    let relay_secret = match &config.relay_secret_file {
        Some(path) => Some(crate::config::Config::secret(path)?),
        None => None,
    };
    let replay =
        replay::DatabaseReplay::start(db.community(scope).map_err(Error::Unavailable.redact())?)
            .await?;
    Ok(Some(std::sync::Arc::new(Gateway {
        authorities: std::sync::Arc::new(Live { own: config.authority.clone(), hub }),
        keys,
        replay: std::sync::Arc::new(replay),
        mutating: std::sync::Arc::new(mutating),
        relay_secret,
        max_inner_response: 1 << 20,
        clock: system_clock,
    })))
}

/// Unknown paths count as state-changing; only declared checks skip the table.
#[cfg(feature = "ohttp")]
fn mutating(path: &str) -> bool {
    path.strip_prefix("/v1/")
        .and_then(crate::api::action)
        .is_none_or(|action| action.effect != crate::api::Effect::Check)
}

#[cfg(feature = "ohttp")]
mod replay {
    use super::{Error, Result};
    use cblv::replay::{BoxFuture, Id, Insert, ReplayStore, StoreError};
    use crlt::params;
    use std::sync::atomic::{AtomicU64, Ordering};

    const PRUNE: &str = "DELETE FROM cvld_ohttp_replay WHERE expires_at <= ?1";
    const GET: &str = "SELECT expires_at FROM cvld_ohttp_replay WHERE id = ?1";
    const INSERT: &str = "INSERT INTO cvld_ohttp_replay (id, expires_at) VALUES (?1, ?2)";
    const EPOCH_GET: &str = "SELECT started_at FROM cvld_ohttp_epoch";
    const EPOCH_SET: &str = "INSERT INTO cvld_ohttp_epoch (started_at) VALUES (?1)";

    /// Replay table in the door database: it survives restarts and is shared by
    /// every instance of the door, so a replay is refused wherever it lands.
    pub(super) struct DatabaseReplay {
        db: crlt::Community,
        started: AtomicU64,
    }

    impl DatabaseReplay {
        pub(super) async fn start(db: crlt::Community) -> Result<Self> {
            let now = cblv::gateway::system_clock();
            let mut tx = db.tx().await.map_err(Error::Unavailable.redact())?;
            let rows = tx
                .query(EPOCH_GET, params![])
                .await
                .map_err(Error::Unavailable.redact())?;
            let started = match rows.first() {
                Some(row) => row.get_i64(0).map_err(Error::Unavailable.redact())? as u64,
                None => {
                    tx.execute(EPOCH_SET, params![now as i64])
                        .await
                        .map_err(Error::Unavailable.redact())?;
                    now
                }
            };
            tx.commit().await.map_err(Error::Unavailable.redact())?;
            Ok(Self {
                db,
                started: AtomicU64::new(started),
            })
        }

        async fn insert(&self, id: Id, expires_at: u64) -> std::result::Result<Insert, StoreError> {
            let now = cblv::gateway::system_clock() as i64;
            let mut tx = self.db.tx().await.map_err(|_| StoreError)?;
            tx.execute(PRUNE, params![now])
                .await
                .map_err(|_| StoreError)?;
            let seen = !tx
                .query(GET, params![id.to_vec()])
                .await
                .map_err(|_| StoreError)?
                .is_empty();
            if !seen {
                tx.execute(INSERT, params![id.to_vec(), expires_at as i64])
                    .await
                    .map_err(|_| StoreError)?;
            }
            tx.commit().await.map_err(|_| StoreError)?;
            Ok(if seen {
                Insert::Replayed
            } else {
                Insert::Fresh
            })
        }
    }

    impl ReplayStore for DatabaseReplay {
        fn insert_if_absent(
            &self,
            id: Id,
            expires_at: u64,
        ) -> BoxFuture<'_, std::result::Result<Insert, StoreError>> {
            Box::pin(self.insert(id, expires_at))
        }
        fn started_at(&self) -> u64 {
            self.started.load(Ordering::SeqCst)
        }
    }
}

#[cfg(all(test, feature = "ohttp"))]
mod tests {
    use super::*;
    use crate::config::{OhttpConfig, OhttpKeyFile};
    use cblv::replay::{Insert, ReplayStore};

    async fn database(path: &std::path::Path) -> crlt::Db {
        let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
            .await
            .unwrap();
        db.migrate(&[crlt::Migration::new(1, "ohttp-replay", SCHEMA)])
            .await
            .unwrap();
        db
    }

    const FAR: u64 = 4_000_000_000;

    #[tokio::test]
    async fn a_replayed_id_is_refused_and_another_is_fresh() {
        let directory = tempfile::tempdir().unwrap();
        let db = database(&directory.path().join("door.db")).await;
        let store = replay::DatabaseReplay::start(db.community("ohttp").unwrap())
            .await
            .unwrap();
        assert_eq!(
            store.insert_if_absent([1; 16], FAR).await,
            Ok(Insert::Fresh)
        );
        assert_eq!(
            store.insert_if_absent([1; 16], FAR).await,
            Ok(Insert::Replayed)
        );
        assert_eq!(
            store.insert_if_absent([2; 16], FAR).await,
            Ok(Insert::Fresh)
        );
    }

    #[tokio::test]
    async fn the_table_and_its_epoch_survive_a_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("door.db");
        let first = {
            let db = database(&path).await;
            let store = replay::DatabaseReplay::start(db.community("ohttp").unwrap())
                .await
                .unwrap();
            assert_eq!(
                store.insert_if_absent([7; 16], FAR).await,
                Ok(Insert::Fresh)
            );
            store.started_at()
        };
        let db = database(&path).await;
        let store = replay::DatabaseReplay::start(db.community("ohttp").unwrap())
            .await
            .unwrap();
        assert_eq!(store.started_at(), first);
        assert_eq!(
            store.insert_if_absent([7; 16], FAR).await,
            Ok(Insert::Replayed)
        );
    }

    #[tokio::test]
    async fn expired_entries_are_pruned() {
        let directory = tempfile::tempdir().unwrap();
        let db = database(&directory.path().join("door.db")).await;
        let store = replay::DatabaseReplay::start(db.community("ohttp").unwrap())
            .await
            .unwrap();
        assert_eq!(store.insert_if_absent([3; 16], 1).await, Ok(Insert::Fresh));
        assert_eq!(
            store.insert_if_absent([3; 16], FAR).await,
            Ok(Insert::Fresh)
        );
    }

    #[tokio::test]
    async fn scopes_do_not_share_replay_ids() {
        let directory = tempfile::tempdir().unwrap();
        let db = database(&directory.path().join("door.db")).await;
        let one = replay::DatabaseReplay::start(db.community("one").unwrap())
            .await
            .unwrap();
        let two = replay::DatabaseReplay::start(db.community("two").unwrap())
            .await
            .unwrap();
        assert_eq!(one.insert_if_absent([9; 16], FAR).await, Ok(Insert::Fresh));
        assert_eq!(two.insert_if_absent([9; 16], FAR).await, Ok(Insert::Fresh));
    }

    #[test]
    fn only_declared_checks_skip_the_replay_table() {
        assert!(!mutating("/v1/login_begin"));
        assert!(mutating("/v1/register_finish"));
        assert!(mutating("/v1/not_an_action"));
        assert!(mutating("/other"));
    }

    fn config(authority: &str, keys: usize, ikm: &str) -> OhttpConfig {
        OhttpConfig {
            authority: authority.into(),
            keys: (0..keys)
                .map(|i| OhttpKeyFile {
                    key_id: i as u8 + 1,
                    ikm_file: ikm.into(),
                    not_after: FAR,
                })
                .collect(),
            relay_secret_file: None,
        }
    }

    #[tokio::test]
    async fn the_gateway_starts_only_for_a_served_authority_with_readable_keys() {
        let directory = tempfile::tempdir().unwrap();
        let db = database(&directory.path().join("door.db")).await;
        let ikm = directory.path().join("ikm");
        std::fs::write(&ikm, [5u8; 32]).unwrap();
        let ikm = ikm.to_str().unwrap();
        let hosts = vec!["api.example.test".to_owned()];
        assert!(build(None, &hosts, &db, "ohttp", None).await.unwrap().is_none());
        let started = build(
            Some(&config("api.example.test", 1, ikm)),
            &hosts,
            &db,
            "ohttp",
            None,
        )
        .await;
        assert!(started.unwrap().is_some());
        for bad in [
            config("other.example.test", 1, ikm),
            config("api.example.test", 0, ikm),
            config("api.example.test", 5, ikm),
            config("api.example.test", 1, "/nonexistent/ikm"),
        ] {
            assert!(build(Some(&bad), &hosts, &db, "ohttp", None).await.is_err());
        }
    }
}

#[cfg(all(test, not(feature = "ohttp")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_configured_gateway_refuses_to_start_without_the_feature() {
        let directory = tempfile::tempdir().unwrap();
        let db = crlt::Db::open(crlt::Config::new(
            format!("file://{}", directory.path().join("door.db").display()),
            "",
        ))
        .await
        .unwrap();
        let config = OhttpConfig {
            authority: "api.example.test".into(),
            keys: Vec::new(),
            relay_secret_file: None,
        };
        assert!(build(None, &[], &db, "ohttp", None).await.unwrap().is_none());
        assert!(build(Some(&config), &[], &db, "ohttp", None).await.is_err());
    }
}
