#![cfg(feature = "development-gate")]

mod support;
use cvld::{
    api::{GlobalPublic, PresentationChallenge, TrustFeed},
    config::{CommunityConfig, RootCommunityConfig},
    service::Door,
};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::AtomicU64};
use support::*;

const ROOT: &str = "api.admin.root.example.test";
const MEMBER_HOST: &str = "api.root.example.test";

fn public_descriptor(community: &str) -> cpsd::RootBoardPublicKey {
    // The service receives only this purpose-specific public descriptor. No
    // root credential issuer secret is serialized or supplied to the door.
    let issuer = cpsd::IssuerKey::generate(
        &mut cpsd::rand::rngs::OsRng,
        cpsd::KeyId::new("root-test").unwrap(),
        vec![cpsd::GateId::new("root-board").unwrap()],
    )
    .unwrap()
    .public_key()
    .clone();
    cpsd::RootBoardPublicKey::from_authenticated_beacon(
        issuer,
        cpsd::CommunityId::new(community).unwrap(),
        1,
        NOW / cpsd::ROOT_BOARD_COHORT_SECONDS * cpsd::ROOT_BOARD_COHORT_SECONDS,
    )
    .unwrap()
}

async fn root_board(public: &GlobalPublic) -> (Running, cpsd::RootBoardPublicKey) {
    let descriptor = public_descriptor("root");
    (root_with_descriptor(public, &descriptor).await, descriptor)
}

async fn root_with_descriptor(
    public: &GlobalPublic,
    descriptor: &cpsd::RootBoardPublicKey,
) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let config = community_config(dir.path(), "root", public, 100);
    let descriptor_path = dir.path().join("root-public");
    std::fs::write(&descriptor_path, descriptor.to_bytes()).unwrap();
    let config =
        RootCommunityConfig::new(config, descriptor_path.to_str().unwrap().into()).unwrap();
    std::fs::write(
        dir.path().join("root-config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let door = Door::root_board(config, clock.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Running {
        base,
        door,
        clock,
        task,
        dir,
    }
}

async fn feed(service: &Running, host: &str) -> TrustFeed {
    serde_json::from_value(
        client(service, host, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap()
}

fn descriptor(feed: &TrustFeed, now: u64) -> cpsd::RootBoardPublicKey {
    let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    let verified = ring
        .verify(
            feed.root_board
                .as_ref()
                .expect("root descriptor in public feed"),
            csgn::Kind::SettingsSnapshot,
            now,
        )
        .unwrap();
    let publication: Value = serde_json::from_slice(verified.payload()).unwrap();
    let manifest = ring
        .verify(&feed.manifest, csgn::Kind::SettingsSnapshot, now)
        .unwrap();
    let manifest: cmty::cplc::TrustManifest = serde_json::from_slice(manifest.payload()).unwrap();
    assert_eq!(manifest.community, "root");
    assert_eq!(manifest.revision, feed.revision);
    assert_eq!(manifest.policy_epoch, feed.policy_epoch);
    assert_eq!(manifest.key_ring, feed.key_ring);
    assert_eq!(
        manifest.root_board_revision,
        Some(publication["revision"].as_u64().unwrap())
    );
    assert_eq!(publication["community"], "root");
    assert_eq!(publication["policy_epoch"], feed.policy_epoch);
    let bytes: Vec<u8> = serde_json::from_value(publication["descriptor"].clone()).unwrap();
    let descriptor = cpsd::RootBoardPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(descriptor.policy_epoch(), feed.policy_epoch);
    assert_eq!(descriptor.community().as_bytes(), b"root");
    assert!(now >= descriptor.cohort_start());
    assert!(now < descriptor.expires_at());
    assert!(verified.valid_until() <= descriptor.expires_at());
    descriptor
}

#[tokio::test(flavor = "multi_thread")]
async fn root_operator_admin_authority_is_local_to_the_explicit_root_board() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let ordinary = community("alpha", &public).await;
    let (mut board, configured) = root_board(&public).await;
    let before = feed(&board, MEMBER_HOST).await;
    assert_eq!(
        descriptor(&before, NOW).issuer().to_bytes(),
        configured.issuer().to_bytes()
    );
    assert!(
        feed(&ordinary, "api.alpha.example.test")
            .await
            .root_board
            .is_none()
    );

    // The ordinary constructor cannot infer root trust from a community name.
    let dir = tempfile::tempdir().unwrap();
    let config = community_config(dir.path(), "root", &public, 100);
    assert!(Door::community(config, board.clock.clone()).await.is_err());
    assert_eq!(
        call_status(
            &board,
            ROOT,
            None,
            "register_begin",
            json!({
                "bootstrap": "synthetic-admin-enrolment-capability", "passport": null,
            })
        )
        .await,
        403
    );
    let root = enrol(&board, ROOT, Some("synthetic-root-enrolment-capability")).await;
    let source_root = enrol(
        &ordinary,
        support::ROOT,
        Some("synthetic-root-enrolment-capability"),
    )
    .await;
    let admin_host = "api.admin.alpha.example.test";
    let admin = enrol(
        &ordinary,
        admin_host,
        Some("synthetic-admin-enrolment-capability"),
    )
    .await;
    let schema = json!({"schema": community_schema("root", 2)});
    assert_eq!(
        call_status(&board, ROOT, None, "schema_check", schema.clone()).await,
        401
    );
    assert_eq!(
        call_status(
            &board,
            ROOT,
            Some(&root.session),
            "schema_check",
            schema.clone()
        )
        .await,
        200
    );
    assert_eq!(
        call_status(
            &ordinary,
            support::ROOT,
            Some(&source_root.session),
            "schema_check",
            json!({"schema": community_schema("alpha", 2)})
        )
        .await,
        403
    );
    assert_eq!(
        call_status(
            &ordinary,
            admin_host,
            Some(&admin.session),
            "schema_check",
            json!({"schema": community_schema("alpha", 2)})
        )
        .await,
        200
    );
    assert_eq!(
        call_status(
            &board,
            ROOT,
            Some(&source_root.session),
            "schema_check",
            schema.clone()
        )
        .await,
        401
    );
    assert_eq!(
        call_status(
            &board,
            MEMBER_HOST,
            Some(&root.session),
            "schema_check",
            schema.clone()
        )
        .await,
        401
    );
    assert_eq!(
        call_status(&board, ROOT, Some(&root.session), "lobby", json!({})).await,
        403
    );
    for host in [
        "api.admin.alpha.example.test",
        "api.admin.root.example.test.evil.test",
        "api.admin.root.example.test:443",
        "api.admin.root.example.test.",
        "alias.example.test",
        "api.root.example.test.evil.test",
    ] {
        assert_eq!(
            call_status(
                &board,
                host,
                Some(&root.session),
                "schema_check",
                schema.clone()
            )
            .await,
            421,
            "{host}"
        );
    }

    let later = NOW + 86_400;
    let setting = json!({"key": "quota", "value": 5, "inherit": false, "effective_at": later});
    assert_eq!(
        call_status(
            &ordinary,
            support::ROOT,
            Some(&source_root.session),
            "setting_set",
            setting.clone()
        )
        .await,
        403
    );
    assert_eq!(
        call_status(&board, ROOT, Some(&root.session), "setting_set", setting).await,
        200
    );

    let changed: TrustFeed = serde_json::from_value(
        client(&board, ROOT, Some(&root.session))
            .call("schema_set", schema)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(changed.policy_epoch > before.policy_epoch);
    assert_eq!(
        descriptor(&changed, NOW).issuer().to_bytes(),
        configured.issuer().to_bytes()
    );
    let schema_snapshot: cmty::cplc::Snapshot<cmty::cplc::cshm::Schema> =
        cmty::cplc::verify_snapshot(
            &csgn::KeyRing::from_cbor(&changed.key_ring).unwrap(),
            &changed.schema,
            cmty::cplc::SnapshotExpectation {
                community: "root",
                kind: cmty::cplc::SnapshotKind::Schema,
                minimum_revision: 1,
                policy_epoch: changed.policy_epoch,
                now: NOW,
            },
        )
        .unwrap();
    assert_eq!(schema_snapshot.content.version, 2);
    board.clock.set(later);
    board.door.maintain().await.unwrap();
    let maintained = feed(&board, MEMBER_HOST).await;
    assert!(maintained.policy_epoch > changed.policy_epoch);
    assert_eq!(
        descriptor(&maintained, later).issuer().to_bytes(),
        configured.issuer().to_bytes()
    );

    // Reopen from the same public descriptor file; its old epoch is not an
    // instruction to roll the durable policy backwards or replace the issuer.
    board.task.abort();
    let config =
        RootCommunityConfig::read(board.dir.path().join("root-config.json").to_str().unwrap())
            .unwrap();
    board.door = Door::root_board(config, board.clock.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    board.base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(board.door.clone());
    board.task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let reopened = feed(&board, MEMBER_HOST).await;
    assert_eq!(reopened.policy_epoch, maintained.policy_epoch);
    assert_eq!(
        descriptor(&reopened, later).issuer().to_bytes(),
        configured.issuer().to_bytes()
    );
    std::fs::write(
        board.dir.path().join("root-public"),
        public_descriptor("root").to_bytes(),
    )
    .unwrap();
    let config =
        RootCommunityConfig::read(board.dir.path().join("root-config.json").to_str().unwrap())
            .unwrap();
    assert!(matches!(
        Door::root_board(config, board.clock.clone()).await,
        Err(cvld::error::Error::Refused)
    ));
}

#[path = "root_board/journey.rs"]
mod journey;
#[path = "root_board/refusals.rs"]
mod refusals;
