use super::*;
use crate::test_support as support;
use support::*;

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
    assert!(Door::community(config, global.clock.clone()).await.is_ok());
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
    let root = enrol(
        &global,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    client(&global, ROOT, Some(&root.session))
        .call("global_warn", serde_json::json!({"user":member.user}))
        .await
        .unwrap();
    assert!(matches!(
        client(&global, WALLET, Some(&member.session))
            .call("global_warn", serde_json::json!({"user":member.user}))
            .await,
        Err(Error::Forbidden)
    ));
}
