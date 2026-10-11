//! Real configured host construction; issuance authority is tested by the linked
//! garden journey. These unconfigured-account cases do not qualify native joins.
use super::*;
use serde_json::{Value, json};
use std::path::Path;

#[path = "../../../tests/support/mod.rs"]
mod support;

struct Fixture {
    directory: tempfile::TempDir,
    bundle: String,
    source: String,
    clock: Arc<support::TestClock>,
    _global: support::Running,
}
fn write(path: &Path, value: &impl serde::Serialize) -> String {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    path.to_str().unwrap().into()
}
impl Fixture {
    async fn new() -> Self {
        let global = support::global(100).await;
        let public: api::GlobalPublic = serde_json::from_value(
            support::client(&global, support::WALLET, None)
                .call("global_public", json!({}))
                .await
                .unwrap(),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let root_dir = directory.path().join("root");
        let source_dir = directory.path().join("source");
        std::fs::create_dir(&root_dir).unwrap();
        std::fs::create_dir(&source_dir).unwrap();
        let key = cpsd::IssuerKey::generate(
            &mut cpsd::rand::rngs::OsRng,
            cpsd::KeyId::new("root-purpose").unwrap(),
            vec![cpsd::GateId::new("root-board").unwrap()],
        )
        .unwrap();
        let descriptor = cpsd::RootBoardPublicKey::from_authenticated_beacon(
            key.public_key().clone(),
            cpsd::CommunityId::new("root").unwrap(),
            1,
            support::NOW / cpsd::ROOT_BOARD_COHORT_SECONDS * cpsd::ROOT_BOARD_COHORT_SECONDS,
        )
        .unwrap();
        let public_file = root_dir.join("root-public");
        std::fs::write(&public_file, descriptor.to_bytes()).unwrap();
        let mut root = support::community_config(&root_dir, "root", &public, 100);
        root.shutdown_seconds = 11;
        let root = RootCommunityConfig::new(root, public_file.to_str().unwrap().into()).unwrap();
        let root_file = write(&root_dir.join("root.json"), &root);
        let mut source = support::community_config(&source_dir, "alpha", &public, 100);
        source.listen = "127.0.0.2:0".into();
        source.shutdown_seconds = 7;
        let source = write(&source_dir.join("source.json"), &source);
        let key_file = root_dir.join("purpose-secret");
        std::fs::write(&key_file, key.to_secret_bytes()).unwrap();
        let bundle = write(
            &directory.path().join("issuer.json"),
            &json!({"root_board_config":root_file,"source_configs":[source],
                "purpose_key_file":key_file.to_str().unwrap()}),
        );
        Self {
            directory,
            bundle,
            source,
            clock: Arc::new(support::TestClock(std::sync::atomic::AtomicU64::new(
                support::NOW,
            ))),
            _global: global,
        }
    }
    fn source_change(&self, key: &str, value: Value) {
        let mut source: Value =
            serde_json::from_slice(&std::fs::read(&self.source).unwrap()).unwrap();
        source[key] = value;
        write(Path::new(&self.source), &source);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_argv_and_config_bind_one_purpose_to_all_hosts_before_listening() {
    let fixture = Fixture::new().await;
    let matches = cli::command()
        .try_get_matches_from(["cvld", "serve", "root-issuer", "--config", &fixture.bundle])
        .unwrap();
    let (_, serve) = matches.subcommand().unwrap();
    let (scope, selected) = serve.subcommand().unwrap();
    assert_eq!(scope, "root-issuer");
    let config = config::read(selected.get_one::<String>("config").unwrap()).unwrap();
    assert_eq!(config.budget, Duration::from_secs(7));
    let construction = NativeConstruction::new();
    let mut services = Vec::new();
    let mut listeners = Vec::new();
    open_components(
        config.root,
        config.sources,
        config.key,
        fixture.clock,
        &construction,
        &mut services,
        &mut listeners,
    )
    .await
    .unwrap();
    assert_eq!(services.len(), 2);
    assert_eq!(listeners.len(), 2);
    assert_ne!(
        listeners[0].local_addr().unwrap(),
        listeners[1].local_addr().unwrap()
    );
    // A different private key cannot replace the root descriptor
    // selected by the genuine configured publication owner.
    let other = cpsd::IssuerKey::generate(
        &mut cpsd::rand::rngs::OsRng,
        cpsd::KeyId::new("other-root").unwrap(),
        vec![cpsd::GateId::new("root-board").unwrap()],
    )
    .unwrap();
    assert!(services[0].door.root_board_purpose(other).await.is_err());
    drop(listeners);
    lifecycle::close(&services, &construction).await.unwrap();
    lifecycle::close(&services, &construction).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflicting_identity_domain_and_bind_refuse_during_configuration() {
    let fixture = Fixture::new().await;
    let original = std::fs::read(&fixture.source).unwrap();
    for (field, value) in [
        ("community", "root"),
        ("domain", "other.test"),
        ("listen", "127.0.0.1:0"),
        ("listen", "0.0.0.0:0"),
        ("listen", "[::]:0"),
        ("listen", "[::ffff:127.0.0.1]:0"),
        ("community", "alpha/path"),
        ("domain", "example.test?query"),
    ] {
        fixture.source_change(field, json!(value));
        assert!(
            matches!(config::read(&fixture.bundle), Err(Error::Invalid)),
            "{field}"
        );
        std::fs::write(&fixture.source, &original).unwrap();
    }
    let mut bundle: Value =
        serde_json::from_slice(&std::fs::read(&fixture.bundle).unwrap()).unwrap();
    bundle["source_configs"] = json!([fixture.source, fixture.source]);
    write(Path::new(&fixture.bundle), &bundle);
    assert!(matches!(config::read(&fixture.bundle), Err(Error::Invalid)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_later_factory_retains_and_closes_earlier_doors_without_listeners() {
    let fixture = Fixture::new().await;
    fixture.source_change(
        "schema_file",
        json!(fixture.directory.path().join("missing-schema")),
    );
    let config = config::read(&fixture.bundle).unwrap();
    let construction = NativeConstruction::new();
    let mut services = Vec::new();
    let mut listeners = Vec::new();
    assert!(
        open_components(
            config.root,
            config.sources,
            config.key,
            fixture.clock,
            &construction,
            &mut services,
            &mut listeners
        )
        .await
        .is_err()
    );
    assert_eq!(services.len(), 1);
    assert!(listeners.is_empty());
    lifecycle::close(&services, &construction).await.unwrap();
    lifecycle::close(&services, &construction).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_secret_and_unknown_bundle_fields_refuse_before_factories() {
    let fixture = Fixture::new().await;
    let mut bundle: Value =
        serde_json::from_slice(&std::fs::read(&fixture.bundle).unwrap()).unwrap();
    bundle["source_private_key"] = json!("not-a-supported-authority");
    write(Path::new(&fixture.bundle), &bundle);
    assert!(matches!(config::read(&fixture.bundle), Err(Error::Invalid)));
    bundle.as_object_mut().unwrap().remove("source_private_key");
    write(Path::new(&fixture.bundle), &bundle);
    std::fs::write(bundle["purpose_key_file"].as_str().unwrap(), b"invalid-key").unwrap();
    assert!(matches!(config::read(&fixture.bundle), Err(Error::Invalid)));
}
