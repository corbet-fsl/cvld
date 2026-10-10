//! Trusted configuration, publication rollback and physical database boundaries.
use super::*;
#[cfg(feature = "development-gate")]
use crate::global_trust;
use crate::test_support as support;
use crate::{config::CommunityConfig, identity};
#[cfg(feature = "development-gate")]
use support::community_config;
use support::{NOW, global_config};

async fn database(path: &std::path::Path) -> Db {
    Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_configuration_reads_preserve_categories_and_secret_bounds() {
    let directory = tempfile::tempdir().unwrap();
    let config = global_config(directory.path(), 100).await;
    let path = directory.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let loaded = Config::read(path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.domain, config.domain);
    assert_eq!(loaded.root_user, config.root_user);
    let mut extra = serde_json::to_value(&config).unwrap();
    extra["private-unknown-setting"] = serde_json::json!("private-config-marker");
    std::fs::write(&path, serde_json::to_vec(&extra).unwrap()).unwrap();
    assert!(matches!(
        Config::read(path.to_str().unwrap()),
        Err(Error::Invalid)
    ));
    std::fs::write(&path, b"private-malformed-json").unwrap();
    assert!(matches!(
        Config::read(path.to_str().unwrap()),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        CommunityConfig::read(path.to_str().unwrap()),
        Err(Error::Invalid)
    ));
    let missing = directory.path().join("private-missing-file");
    assert!(matches!(
        Config::read(missing.to_str().unwrap()),
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        CommunityConfig::read(missing.to_str().unwrap()),
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        Config::secret(missing.to_str().unwrap()),
        Err(Error::Unavailable)
    ));
    for length in [0, 31, 33] {
        std::fs::write(&path, vec![17; length]).unwrap();
        assert!(matches!(
            Config::seed(path.to_str().unwrap()),
            Err(Error::Invalid)
        ));
    }
    std::fs::write(&path, [17; 32]).unwrap();
    assert_eq!(Config::seed(path.to_str().unwrap()).unwrap(), [17; 32]);
    assert_eq!(
        Config::secret(path.to_str().unwrap()).unwrap().as_slice(),
        &[17; 32]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn database_identity_refuses_role_or_scope_rebinding_and_missing_schema() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("identity.db");
    let db = database(&path).await;
    assert!(matches!(
        identity::bind(&db, "global", "global").await,
        Err(Error::Unavailable)
    ));
    db.migrate(&[Migration::new(1, "service", identity::SCHEMA)])
        .await
        .unwrap();
    identity::bind(&db, "global", "global").await.unwrap();
    drop(db);
    let db = database(&path).await;
    assert_eq!(
        db.migrate(&[Migration::new(1, "service", identity::SCHEMA)])
            .await
            .unwrap(),
        0
    );
    identity::bind(&db, "global", "global").await.unwrap();
    for (kind, scope) in [("community", "global"), ("global", "other")] {
        assert!(matches!(
            identity::bind(&db, kind, scope).await,
            Err(Error::Invalid)
        ));
    }
    identity::bind(&db, "global", "global").await.unwrap();
    let scope = db.community("cvld:service").unwrap();
    scope
        .execute(
            "UPDATE cvld_service SET kind = ?1",
            crlt::params![vec![1u8, 2]],
        )
        .await
        .unwrap();
    assert!(matches!(
        identity::bind(&db, "global", "global").await,
        Err(Error::Unavailable)
    ));
}

#[cfg(feature = "development-gate")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reopening_publication_preserves_authority_and_refreshes_the_watch() {
    let directory = tempfile::tempdir().unwrap();
    let config = global_config(directory.path(), 100).await;
    let db = database(&directory.path().join("global.db")).await;
    let first = GlobalService::open(&db, &config, NOW).await.unwrap();
    let original = first.public.clone();
    drop(first);
    let mut second = GlobalService::open(&db, &config, NOW).await.unwrap();
    assert_eq!(second.public.key_ring, original.key_ring);
    assert_eq!(second.public.issuer, original.issuer);
    let mut watch = second.changes.subscribe();
    second.refresh(NOW + 86_400).await.unwrap();
    watch.changed().await.unwrap();
    let refreshed = watch.borrow().clone();
    assert_ne!(refreshed.status, original.status);
    let ring = csgn::KeyRing::from_cbor(&refreshed.key_ring).unwrap();
    let status =
        cgbl::Status::verify(&refreshed.status, &ring, "global", 1, 1, NOW + 86_400).unwrap();
    assert_eq!(status.epoch, 1);
    assert_eq!(status.policy_revision, 1);
    drop(second);
    let mut restarted = GlobalService::open(&db, &config, NOW + 86_401)
        .await
        .unwrap();
    assert_eq!(restarted.public.key_ring, original.key_ring);
    assert_eq!(restarted.public.issuer, original.issuer);
    assert!(matches!(
        GlobalService::open(&db, &config, NOW).await,
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        restarted.refresh(NOW + config.signer_max_seconds + 1).await,
        Err(Error::Refused)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn development_issuer_cannot_be_enabled_by_a_production_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = global_config(directory.path(), 100).await;
    let db = database(&directory.path().join("global.db")).await;
    config.development = false;
    assert!(matches!(
        GlobalService::open(&db, &config, NOW).await,
        Err(Error::Unavailable)
    ));
    #[cfg(not(feature = "development-gate"))]
    {
        config.development = true;
        assert!(matches!(
            GlobalService::open(&db, &config, NOW).await,
            Err(Error::Forbidden)
        ));
    }
}

#[cfg(feature = "development-gate")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_signer_and_policy_refuse_substituted_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let config = global_config(directory.path(), 100).await;
    let db = database(&directory.path().join("global.db")).await;
    GlobalService::open(&db, &config, NOW).await.unwrap();
    std::fs::write(&config.signing_seed_file, [91; 32]).unwrap();
    assert!(matches!(
        GlobalService::open(&db, &config, NOW).await,
        Err(Error::Unavailable)
    ));
    std::fs::write(&config.signing_seed_file, [4; 32]).unwrap();
    std::fs::write(&config.policy_authority_file, b"private-invalid-authority").unwrap();
    assert!(matches!(
        GlobalService::open(&db, &config, NOW).await,
        Err(Error::Invalid)
    ));
}

#[cfg(feature = "development-gate")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_trust_refuses_tampering_and_retains_durable_rollback_floors() {
    let global_directory = tempfile::tempdir().unwrap();
    let config = global_config(global_directory.path(), 100).await;
    let global_db = database(&global_directory.path().join("global.db")).await;
    let global = GlobalService::open(&global_db, &config, NOW).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = community_config(directory.path(), "alpha", &global.public, 100);
    let path = directory.path().join("community.db");
    let config_path = directory.path().join("config.json");
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let config = CommunityConfig::read(config_path.to_str().unwrap()).unwrap();
    assert_eq!(config.community, "alpha");
    let db = database(&path).await;
    assert!(matches!(
        global_trust::load(&db, &config, NOW).await,
        Err(Error::Unavailable)
    ));
    db.migrate(&[Migration::new(1, "global-trust", global_trust::SCHEMA)])
        .await
        .unwrap();
    let first = global_trust::load(&db, &config, NOW).await.unwrap();
    assert_eq!(first.status.epoch, 1);
    assert_eq!(first.status.policy_revision, 1);
    assert!(first.valid_until > NOW);
    assert!(!first.signing_keys.is_empty());
    global_trust::load(&db, &config, NOW).await.unwrap();

    let mut tampered = global.public.status.clone();
    let last = tampered.last_mut().unwrap();
    *last ^= 1;
    std::fs::write(&config.global_status_file, tampered).unwrap();
    assert!(matches!(
        global_trust::load(&db, &config, NOW).await,
        Err(Error::Refused)
    ));
    std::fs::write(&config.global_status_file, &global.public.status).unwrap();
    let scope = db.community("alpha").unwrap();
    scope
        .execute(
            "UPDATE cvld_global_trust SET epoch = ?1, revision = ?2",
            crlt::params![2, 2],
        )
        .await
        .unwrap();
    drop(scope);
    drop(db);
    let reopened = database(&path).await;
    assert_eq!(
        reopened
            .migrate(&[Migration::new(1, "global-trust", global_trust::SCHEMA)])
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        global_trust::load(&reopened, &config, NOW).await,
        Err(Error::Refused)
    ));
    let rows = reopened
        .community("alpha")
        .unwrap()
        .query("SELECT epoch, revision FROM cvld_global_trust", ())
        .await
        .unwrap();
    assert_eq!(rows[0].get_i64(0).unwrap(), 2);
    assert_eq!(rows[0].get_i64(1).unwrap(), 2);
}
