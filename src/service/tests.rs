use super::*;
use crate::test_support as support;
use support::*;

#[path = "tests/timing.rs"]
mod timing;

#[tokio::test]
async fn live_lifecycle_clocks_do_not_change_the_original_proof_context() {
    let clock = TestClock(std::sync::atomic::AtomicU64::new(NOW));
    assert_eq!(operation_time(&clock), NOW);
    at(NOW, async {
        clock.set(NOW + 1);
        assert_eq!(operation_time(&clock), NOW);
        with_live_clock(async {
            assert_eq!(operation_time(&clock), NOW + 1);
            tokio::task::yield_now().await;
            clock.set(NOW + 2);
            assert_eq!(operation_time(&clock), NOW + 2);
        })
        .await;
        assert_eq!(operation_time(&clock), NOW);
    })
    .await;
    assert_eq!(operation_time(&clock), NOW + 2);
}

fn anonymous(host: &str) -> Context {
    Context {
        host: host.into(),
        grant: None,
        token: None,
        now: NOW,
        authentication: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_global_configuration_fails_before_serving() {
    for (field, value) in [
        ("shutdown_seconds", serde_json::json!(0)),
        ("shutdown_seconds", serde_json::json!(u64::MAX)),
        ("domain", serde_json::json!("")),
        ("domain", serde_json::json!("UPPER.example")),
        ("publication_seconds", serde_json::json!(1)),
        ("publication_seconds", serde_json::json!(172801)),
        ("throttle_burst", serde_json::json!(0)),
        ("throttle_interval_ms", serde_json::json!(0)),
        ("root_user", serde_json::json!("not-a-uuid")),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = global_config(dir.path(), 100).await;
        let mut encoded = serde_json::to_value(config).unwrap();
        encoded[field] = value;
        let config = serde_json::from_value(encoded).unwrap();
        assert!(
            matches!(
                Door::global(
                    config,
                    Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)))
                )
                .await,
                Err(Error::Invalid)
            ),
            "{field}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let mut config = global_config(dir.path(), 100).await;
    let token = dir.path().join("token");
    std::fs::write(&token, [255]).unwrap();
    config.database_token_file = Some(token.to_str().unwrap().into());
    assert!(matches!(
        Door::global(config, Arc::new(SystemClock)).await,
        Err(Error::Invalid)
    ));
    let mut config = global_config(dir.path(), 100).await;
    std::fs::write(&token, []).unwrap();
    config.database_token_file = Some(token.to_str().unwrap().into());
    config.root_bootstrap_file = None;
    config.domain = "example-1.test".into();
    assert!(
        Door::global(
            config,
            Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)))
        )
        .await
        .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn community_configuration_enforces_host_and_publication_boundaries() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", serde_json::json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    for (field, value) in [
        ("shutdown_seconds", serde_json::json!(0)),
        ("shutdown_seconds", serde_json::json!(u64::MAX)),
        ("domain", serde_json::json!("")),
        ("domain", serde_json::json!("UPPER.example")),
        ("publication_seconds", serde_json::json!(1)),
        ("publication_seconds", serde_json::json!(172801)),
        ("throttle_burst", serde_json::json!(0)),
        ("throttle_interval_ms", serde_json::json!(0)),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = community_config(dir.path(), "negative", &public, 100);
        let mut encoded = serde_json::to_value(config).unwrap();
        encoded[field] = value;
        let config = serde_json::from_value(encoded).unwrap();
        assert!(
            matches!(
                Door::community(
                    config,
                    Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)))
                )
                .await,
                Err(Error::Invalid)
            ),
            "{field}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let mut config = community_config(dir.path(), "negative", &public, 100);
    let token = dir.path().join("token");
    std::fs::write(&token, [255]).unwrap();
    config.database_token_file = Some(token.to_str().unwrap().into());
    assert!(matches!(
        Door::community(config, global.clock.clone()).await,
        Err(Error::Invalid)
    ));
    let mut config = community_config(dir.path(), "negative", &public, 100);
    std::fs::write(&token, []).unwrap();
    config.database_token_file = Some(token.to_str().unwrap().into());
    config.root.bootstrap_file = None;
    config.admin.bootstrap_file = None;
    config.domain = "example-1.test".into();
    assert!(Door::community(config, global.clock.clone()).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_bootstrap_configuration_rejects_nontext_and_short_secrets() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", serde_json::json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    for bytes in [vec![255], b"short".to_vec()] {
        let dir = tempfile::tempdir().unwrap();
        let config = global_config(dir.path(), 100).await;
        std::fs::write(config.root_bootstrap_file.as_ref().unwrap(), &bytes).unwrap();
        assert!(matches!(
            Door::global(config, global.clock.clone()).await,
            Err(Error::Invalid)
        ));
        let dir = tempfile::tempdir().unwrap();
        let config = community_config(dir.path(), "bootstrap", &public, 100);
        std::fs::write(config.admin.bootstrap_file.as_ref().unwrap(), &bytes).unwrap();
        assert!(matches!(
            Door::community(config, global.clock.clone()).await,
            Err(Error::Invalid)
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn internal_context_and_backend_access_remain_scoped() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", serde_json::json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community("boundaries", &public).await;
    assert!(community.door.allows_origin(
        "api.boundaries.example.test",
        "https://boundaries.example.test"
    ));
    assert!(community.door.allows_origin(
        "api.boundaries.example.test",
        "https://vault.boundaries.example.test"
    ));
    assert!(!community.door.allows_origin(
        "api.boundaries.example.test",
        "https://foreign.example.test"
    ));
    assert!(matches!(
        anonymous(WALLET).member(),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        anonymous(WALLET).subject(),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        anonymous(WALLET).global_session(),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        global.door.community_backend(),
        Err(Error::WrongHost)
    ));
    assert!(matches!(
        global.door.community_public(),
        Err(Error::WrongHost)
    ));
    assert!(matches!(
        community.door.global_backend(),
        Err(Error::WrongHost)
    ));
    assert!(matches!(
        community
            .door
            .global_public(anonymous(WALLET), Empty {})
            .await,
        Err(Error::WrongHost)
    ));
    assert!(matches!(
        global.door.logout(anonymous(WALLET), Empty {}).await,
        Err(Error::Unauthorized)
    ));
    assert!(SystemClock.now() > 1_600_000_000);
    let member = enrol(&global, WALLET, None).await;
    client(&global, WALLET, Some(&member.session))
        .call("development_gate", serde_json::json!({}))
        .await
        .unwrap();
    assert!(matches!(
        client(&global, WALLET, Some(&member.session))
            .call(
                "community_terminate",
                serde_json::json!({"address":"alpha12345","reason":"legal"})
            )
            .await,
        Err(Error::Forbidden)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_budget_is_required_in_each_service_configuration() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", serde_json::json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("configuration.json");
    let mut encoded = serde_json::to_value(global_config(dir.path(), 100).await).unwrap();
    encoded.as_object_mut().unwrap().remove("shutdown_seconds");
    std::fs::write(&path, serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(matches!(
        Config::read(path.to_str().unwrap()),
        Err(Error::Invalid)
    ));
    let mut encoded =
        serde_json::to_value(community_config(dir.path(), "budget", &public, 100)).unwrap();
    encoded.as_object_mut().unwrap().remove("shutdown_seconds");
    std::fs::write(&path, serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(matches!(
        CommunityConfig::read(path.to_str().unwrap()),
        Err(Error::Invalid)
    ));
}
