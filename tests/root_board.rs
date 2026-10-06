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
    let source_root = enrol(&ordinary, ROOT, Some("synthetic-root-enrolment-capability")).await;
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
            ROOT,
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
            ROOT,
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

#[tokio::test(flavor = "multi_thread")]
async fn root_registration_refuses_an_otherwise_valid_ordinary_passport_proof() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let (board, _) = root_board(&public).await;
    let feed = feed(&board, MEMBER_HOST).await;
    let challenge: PresentationChallenge = serde_json::from_value(
        client(&board, MEMBER_HOST, None)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("root").unwrap(),
        csgn::KeyRing::from_cbor(&feed.key_ring).unwrap(),
    );
    let request = expected
        .authenticate_root_board_request(&challenge.request, NOW)
        .unwrap();
    assert_eq!(request.root().to_bytes(), descriptor(&feed, NOW).to_bytes());
    assert!(expected.authenticate(&challenge.request, NOW).is_err());
    // Deliberately answer only the original global half of the exact root
    // challenge. The ordinary proof has the right nonce, scope and passport;
    // rejection must come from the mandatory joint root purpose.
    let proof = trusted_presentation(&passport, request.global_request()).await;
    let pseudonym = cpsd::verify(
        &mut cpsd::rand::rngs::OsRng,
        std::slice::from_ref(passport.issuer()),
        request.global_request(),
        &proof,
    )
    .unwrap();
    assert_eq!(
        pseudonym,
        passport.pseudonym(&cpsd::CommunityId::new("root").unwrap())
    );
    let body = json!({"passport": {"challenge": challenge.challenge, "proof": proof.to_bytes()}});
    assert_eq!(
        call_status(&board, MEMBER_HOST, None, "register_begin", body.clone()).await,
        400
    );
    assert_eq!(
        call_status(&board, MEMBER_HOST, None, "register_begin", body).await,
        409
    );
    assert_eq!(
        call_status(
            &board,
            MEMBER_HOST,
            None,
            "register_begin",
            json!({
                "bootstrap": "synthetic-root-enrolment-capability", "passport": null,
            })
        )
        .await,
        403
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn root_constructor_revalidates_deserialized_scope_and_descriptor_bytes() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root-public");
    std::fs::write(&path, b"not a canonical public descriptor").unwrap();
    let config = community_config(dir.path(), "root", &public, 100);
    let value = json!({"community": config, "root_board_public_key_file": path});
    let parsed: RootCommunityConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(matches!(
        Door::root_board(parsed, global.clock.clone()).await,
        Err(cvld::error::Error::Invalid)
    ));
    std::fs::write(&path, public_descriptor("alpha").to_bytes()).unwrap();
    let parsed: RootCommunityConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(matches!(
        Door::root_board(parsed, global.clock.clone()).await,
        Err(cvld::error::Error::Invalid)
    ));
    let mut foreign = value;
    foreign["community"]["community"] = json!("alpha");
    let parsed: RootCommunityConfig = serde_json::from_value(foreign).unwrap();
    assert!(matches!(
        Door::root_board(parsed, global.clock.clone()).await,
        Err(cvld::error::Error::Invalid)
    ));
    let ordinary: CommunityConfig = community_config(dir.path(), "root", &public, 100);
    assert!(RootCommunityConfig::new(ordinary, String::new()).is_err());
}

/// The real global door issues into an opaque holder. The root credential below
/// is a cryptographic fixture issued by its actual purpose key; it does not
/// claim to exercise the still-missing remote source-role authorization service.
async fn opaque_passport(global: &Running) -> (cpsd::OpaqueHolder, GlobalPublic) {
    use cvld::api::Bytes;
    let member = enrol(global, WALLET, None).await;
    let client = client(global, WALLET, Some(&member.session));
    client.call("development_gate", json!({})).await.unwrap();
    let public: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed_and_sealing_key(
        &mut [71; 32],
        &mut [72; 32],
        b"root-door-fixture",
    )
    .unwrap();
    let challenge: Bytes =
        serde_json::from_value(client.call("passport_challenge", json!({})).await.unwrap())
            .unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let request = holder
        .begin_issuance(&mut cpsd::rand::rngs::OsRng, &issuer, &challenge)
        .unwrap();
    let blind: Bytes = serde_json::from_value(
        client
            .call(
                "passport_issue",
                json!({"challenge": challenge.to_bytes().to_vec(), "request": request.to_bytes()}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    holder
        .finish_issuance(&cpsd::BlindPassport::from_bytes(&blind.bytes).unwrap())
        .unwrap();
    (holder, public)
}

async fn root_presentation(
    board: &Running,
    holder: &cpsd::OpaqueHolder,
    session: Option<&str>,
) -> cvld::api::PresentationInput {
    let challenge: PresentationChallenge = serde_json::from_value(
        client(board, MEMBER_HOST, session)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let public = feed(board, MEMBER_HOST).await;
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("root").unwrap(),
        csgn::KeyRing::from_cbor(&public.key_ring).unwrap(),
    );
    let proof = holder
        .present_root_board(
            &mut cpsd::rand::rngs::OsRng,
            &expected,
            &challenge.request,
            NOW,
        )
        .unwrap();
    cvld::api::PresentationInput {
        challenge: challenge.challenge,
        proof: proof.to_bytes(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_joint_http_registration_voucher_and_renewal_remain_ordinary_membership() {
    use cvld::api::{Ceremony, CredentialResponse};
    let global = global(100).await;
    let (mut holder, public) = opaque_passport(&global).await;
    let source = community("alpha", &public).await;
    let mut rng = cpsd::rand::rngs::OsRng;
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("root-door-purpose").unwrap(),
        vec![cpsd::GateId::new("root-board").unwrap()],
    )
    .unwrap();
    let configured = cpsd::RootBoardPublicKey::from_authenticated_beacon(
        issuer.public_key().clone(),
        cpsd::CommunityId::new("root").unwrap(),
        1,
        NOW / cpsd::ROOT_BOARD_COHORT_SECONDS * cpsd::ROOT_BOARD_COHORT_SECONDS,
    )
    .unwrap();
    let board = root_with_descriptor(&public, &configured).await;
    let current = descriptor(&feed(&board, MEMBER_HOST).await, NOW);

    // Authenticate the real source request under that source's original ring.
    let source_feed = feed(&source, "api.alpha.example.test").await;
    let source_anchor = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("alpha").unwrap(),
        csgn::KeyRing::from_cbor(&source_feed.key_ring).unwrap(),
    );
    let source_challenge: PresentationChallenge = serde_json::from_value(
        client(&source, "api.alpha.example.test", None)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let request = source_anchor
        .authenticate(&source_challenge.request, NOW)
        .unwrap();
    let context = cpsd::RootBoardIssuanceContext::new(&mut rng, request, current.clone()).unwrap();
    // An actual signer authenticates only this fixture's root issuance context.
    // The root member door never receives this signer, source proof or issuer key.
    let mut fixture_signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "root",
        csgn::SecretKey::from_seed(&mut [73; 32]),
        NOW - 1,
        86_400,
    )
    .await
    .unwrap();
    let signed = fixture_signer
        .sign(
            csgn::Kind::Credential,
            &context.to_bytes(),
            NOW,
            context.deadline() + 1,
        )
        .await
        .unwrap();
    let fixture_anchor = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("root").unwrap(),
        fixture_signer.key_ring().unwrap().clone(),
    );
    let request = holder
        .begin_root_board_issuance(
            &mut rng,
            &fixture_anchor,
            &signed,
            &source_anchor,
            &source_challenge.request,
            NOW,
        )
        .unwrap();
    let verified = cpsd::verify_root_board_issuance(
        &[cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap()],
        &context,
        &request,
        NOW,
    )
    .unwrap();
    let credential =
        cpsd::issue_blind_root_board(&mut rng, &issuer, &current, verified, NOW).unwrap();
    holder.finish_root_board_issuance(&credential).unwrap();

    let proof = root_presentation(&board, &holder, None).await;
    let body = json!({"passport": proof});
    let start: Ceremony = serde_json::from_value(
        client(&board, MEMBER_HOST, None)
            .call("register_begin", body.clone())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        call_status(&board, MEMBER_HOST, None, "register_begin", body).await,
        409
    );
    let member = finish_enrol(&board, MEMBER_HOST, start).await;
    let client = client(&board, MEMBER_HOST, Some(&member.session));
    let member_id = holder
        .pseudonym(&cpsd::CommunityId::new("root").unwrap())
        .to_hex();
    client
        .call("handle_reserve", json!({"handle":"root_member"}))
        .await
        .unwrap();
    let receipt = voucher("root", &member_id, "root-door-voucher", NOW + 172_800);
    client.call("gate_voucher", receipt.clone()).await.unwrap();
    assert!(client.call("gate_voucher", receipt).await.is_err());
    for _ in 0..2 {
        let proof = root_presentation(&board, &holder, Some(&member.session)).await;
        let body = json!({"presentation":proof,"devices":[member.signing_key]});
        let issued: CredentialResponse =
            serde_json::from_value(client.call("credential_issue", body.clone()).await.unwrap())
                .unwrap();
        assert_eq!(issued.lobby.state, "admitted");
        let feed = feed(&board, MEMBER_HOST).await;
        let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
        let cose = issued.credential.unwrap();
        let verified = ring.verify(&cose, csgn::Kind::Credential, NOW).unwrap();
        assert!(verified.valid_until() <= current.expires_at());
        let claims: cmty::cplc::Credential = serde_json::from_slice(verified.payload()).unwrap();
        assert_eq!(claims.community, "root");
        assert_eq!(claims.member, member_id);
        assert_eq!(claims.gates.len(), 1);
        assert_eq!(claims.gates[0].gate, "cvch");
        let text = std::str::from_utf8(verified.payload()).unwrap();
        for hidden in ["alpha", "root-board", "development", "role"] {
            assert!(!text.contains(hidden));
        }
        assert_eq!(
            call_status(
                &board,
                MEMBER_HOST,
                Some(&member.session),
                "credential_issue",
                body
            )
            .await,
            409
        );
    }
    assert_eq!(
        call_status(
            &board,
            MEMBER_HOST,
            Some(&member.session),
            "schema_check",
            json!({"schema":community_schema("root", 2)})
        )
        .await,
        403
    );
}
