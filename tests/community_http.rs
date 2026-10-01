#![cfg(feature = "development-gate")]
mod support;
use cmty::cplc;
use cvld::api::*;
use serde_json::{Value, json};
use support::*;

fn verified_feed(
    feed: &TrustFeed,
    community: &str,
    now: u64,
) -> cplc::Snapshot<cmty::cplc::crbk::Values> {
    let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    let manifest = ring
        .verify(&feed.manifest, csgn::Kind::SettingsSnapshot, now)
        .unwrap();
    let manifest: cplc::TrustManifest = serde_json::from_slice(manifest.payload()).unwrap();
    assert_eq!(manifest.community, community);
    assert_eq!(manifest.revision, feed.revision);
    assert_eq!(manifest.policy_epoch, feed.policy_epoch);
    assert_eq!(manifest.key_ring, feed.key_ring);
    for (kind, bytes) in [
        (cplc::SnapshotKind::Schema, &feed.schema),
        (cplc::SnapshotKind::SchemaVersions, &feed.schema_versions),
        (cplc::SnapshotKind::Communities, &feed.communities),
        (cplc::SnapshotKind::RevocationList, &feed.revocations),
    ] {
        let _: cplc::Snapshot<Value> = cplc::verify_snapshot(
            &ring,
            bytes,
            cplc::SnapshotExpectation {
                community,
                kind,
                minimum_revision: 1,
                policy_epoch: feed.policy_epoch,
                now,
            },
        )
        .unwrap();
    }
    cplc::verify_snapshot(
        &ring,
        &feed.settings,
        cplc::SnapshotExpectation {
            community,
            kind: cplc::SnapshotKind::Settings,
            minimum_revision: 1,
            policy_epoch: feed.policy_epoch,
            now,
        },
    )
    .unwrap()
}
#[tokio::test(flavor = "multi_thread")]
async fn two_communities_admission_policy_lapse_and_release_over_http() {
    let global = global(100).await;
    let (wallet, passport, public) = wallet_passport(&global).await;
    let alpha = community("alpha", &public).await;
    let beta = community("beta", &public).await;
    let mut foreign_database =
        cvld::config::CommunityConfig::read(beta.dir.path().join("config.json").to_str().unwrap())
            .unwrap();
    foreign_database.database_url =
        format!("file://{}", alpha.dir.path().join("community.db").display());
    assert!(
        cvld::service::Door::community(foreign_database, beta.clock.clone())
            .await
            .is_err()
    );
    let ah = "api.alpha.example.test";
    let bh = "api.beta.example.test";
    let a = enrol_community(&alpha, ah, &passport).await;
    let b = enrol_community(&beta, bh, &passport).await;
    let ac = client(&alpha, ah, Some(&a.session));
    let bc = client(&beta, bh, Some(&b.session));
    let mut ids = Vec::new();
    for (service, host, name, member, client) in
        [(&alpha, ah, "alpha", &a, &ac), (&beta, bh, "beta", &b, &bc)]
    {
        assert_eq!(
            call_status(service, host, Some(&wallet.session), "lobby", json!({})).await,
            401
        );
        assert_eq!(
            call_status(
                service,
                host,
                Some(&member.session),
                "passport_issue",
                json!({})
            )
            .await,
            421
        );
        assert_eq!(
            call_status(
                &global,
                WALLET,
                Some(&wallet.session),
                "credential_issue",
                json!({})
            )
            .await,
            421
        );
        let lobby: Lobby =
            serde_json::from_value(client.call("lobby", json!({})).await.unwrap()).unwrap();
        let expected = passport
            .pseudonym(&cpsd::CommunityId::new(name.as_bytes()).unwrap())
            .to_hex();
        assert_eq!(lobby.member_id, expected);
        assert_ne!(lobby.member_id, wallet.user);
        ids.push(lobby.member_id);
        assert!(
            client
                .call("handle_reserve", json!({"handle":"admin"}))
                .await
                .is_err()
        );
        client
            .call("handle_reserve", json!({"handle":"member_one"}))
            .await
            .unwrap();
        assert!(
            issue_community(service, host, member, &passport)
                .await
                .credential
                .is_none()
        );
        let sealed = cmty::cmbr::PinV2::seal(
            &cpns::FingerprintContext {
                community: name,
                member: &expected,
                field: "restricted",
            },
            b"true",
            &cpns::Salt::from_bytes(vec![11u8; 32]).unwrap(),
        );
        client
            .call("pin_set", json!({"field":"restricted","pin":sealed}))
            .await
            .unwrap();
        let pin: PinResponse = serde_json::from_value(
            client
                .call("pin_get", json!({"field":"restricted"}))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(pin.pin.unwrap().revision, 1);
        let changed_pin = cmty::cmbr::PinV2::seal(
            &cpns::FingerprintContext {
                community: name,
                member: &expected,
                field: "restricted",
            },
            b"false",
            &cpns::Salt::from_bytes(vec![12u8; 32]).unwrap(),
        );
        assert!(
            client
                .call(
                    "pin_change",
                    json!({"field":"restricted","pin":changed_pin,"evidence":[]})
                )
                .await
                .is_err()
        );
        let unchanged: PinResponse = serde_json::from_value(
            client
                .call("pin_get", json!({"field":"restricted"}))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(unchanged.pin.unwrap().revision, 1);
        let body = voucher(name, &expected, "synthetic-voucher", NOW + 172800);
        client.call("gate_voucher", body.clone()).await.unwrap();
        assert!(client.call("gate_voucher", body).await.is_err());
        let issued = issue_community(service, host, member, &passport).await;
        assert_eq!(issued.lobby.state, "admitted");
        let feed: TrustFeed =
            serde_json::from_value(client.call("trust_feed", json!({})).await.unwrap()).unwrap();
        verified_feed(&feed, name, NOW);
        let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
        let verified = ring
            .verify(&issued.credential.unwrap(), csgn::Kind::Credential, NOW)
            .unwrap();
        let credential: cplc::Credential = serde_json::from_slice(verified.payload()).unwrap();
        assert_eq!(credential.member, expected);
        assert_eq!(credential.community, name);
        assert_eq!(credential.policy_epoch, feed.policy_epoch);
        assert_eq!(credential.pins.len(), 1);
    }
    assert_ne!(ids[0], ids[1]);
    assert_ne!(a.user, b.user);
    assert_eq!(
        call_status(&alpha, bh, Some(&a.session), "lobby", json!({})).await,
        421
    );
    assert_eq!(
        call_status(&beta, bh, Some(&a.session), "lobby", json!({})).await,
        401
    );
    assert_eq!(
        call_status(
            &alpha,
            ah,
            Some(&a.session),
            "setting_set",
            json!({"key":"quota","value":5,"inherit":false,"effective_at":NOW+1})
        )
        .await,
        403
    );
    let admin_host = "api.admin.alpha.example.test";
    let admin = enrol(
        &alpha,
        admin_host,
        Some("synthetic-admin-enrolment-capability"),
    )
    .await;
    let admin_client = client(&alpha, admin_host, Some(&admin.session));
    let before: TrustFeed =
        serde_json::from_value(ac.call("trust_feed", json!({})).await.unwrap()).unwrap();
    let watcher = client(&alpha, ah, None);
    let revision = before.revision;
    let watch = tokio::spawn(async move {
        watcher
            .call("trust_changes", json!({"revision":revision}))
            .await
            .unwrap()
    });
    alpha.clock.set(NOW + 1);
    let after: TrustFeed = serde_json::from_value(
        admin_client
            .call(
                "setting_set",
                json!({"key":"quota","value":5,"inherit":false,"effective_at":NOW+1}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(after.policy_epoch > before.policy_epoch);
    assert!(after.revision > before.revision);
    assert_ne!(after.settings, before.settings);
    assert_eq!(verified_feed(&after, "alpha", NOW + 1).content["quota"], 5);
    let changed: Announcement = serde_json::from_value(watch.await.unwrap()).unwrap();
    assert!(changed.changed);
    assert_eq!(changed.revision, after.revision);
    assert!(admin_client.call("platform_set",json!({"setting":{"key":"quota","value":3,"inherit":false,"effective_at":NOW+2},"force":true})).await.is_err());
    let root = enrol(&alpha, ROOT, Some("synthetic-root-enrolment-capability")).await;
    let root_client = client(&alpha, ROOT, Some(&root.session));
    alpha.clock.set(NOW + 2);
    root_client.call("platform_set",json!({"setting":{"key":"quota","value":3,"inherit":false,"effective_at":NOW+2},"force":true})).await.unwrap();
    alpha.clock.set(NOW + 3);
    let forced: TrustFeed = serde_json::from_value(
        admin_client
            .call(
                "setting_set",
                json!({"key":"quota","value":8,"inherit":false,"effective_at":NOW+3}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(verified_feed(&forced, "alpha", NOW + 3).content["quota"], 3);
    let schema = community_schema("alpha", 2);
    admin_client
        .call("schema_check", json!({"schema":schema}))
        .await
        .unwrap();
    let versions: TrustFeed = serde_json::from_value(
        admin_client
            .call("schema_set", json!({"schema":schema}))
            .await
            .unwrap(),
    )
    .unwrap();
    let ring = csgn::KeyRing::from_cbor(&versions.key_ring).unwrap();
    let archive: cplc::Snapshot<cplc::SchemaVersions> = cplc::verify_snapshot(
        &ring,
        &versions.schema_versions,
        cplc::SnapshotExpectation {
            community: "alpha",
            kind: cplc::SnapshotKind::SchemaVersions,
            minimum_revision: 1,
            policy_epoch: versions.policy_epoch,
            now: NOW + 3,
        },
    )
    .unwrap();
    assert_eq!(archive.content.current, 2);
    assert_eq!(
        archive
            .content
            .versions
            .iter()
            .map(|v| v.schema.version)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(archive.content.versions[1].changes.is_some());
    let live = issue_community(&alpha, ah, &a, &passport).await;
    assert!(live.credential.is_some());
    let before_withdraw: TrustFeed =
        serde_json::from_value(ac.call("trust_feed", json!({})).await.unwrap()).unwrap();
    let proof = presentation(&alpha, ah, Some(&a.session), &passport).await;
    let lapsed: CredentialResponse = serde_json::from_value(ac.call("gate_withdraw", json!({
        "gate":"cvch", "provider":"sponsor", "credential":{"presentation":proof,"devices":vec![[42u8;32]]}
    })).await.unwrap()).unwrap();
    assert!(lapsed.credential.is_none());
    assert_eq!(lapsed.lobby.state, "lapsed");
    let lapsed_feed: TrustFeed =
        serde_json::from_value(ac.call("trust_feed", json!({})).await.unwrap()).unwrap();
    assert!(lapsed_feed.policy_epoch > before_withdraw.policy_epoch);
    // A failed gate is recoverable; an epoch invalidation must not become a permanent ban.
    ac.call(
        "gate_voucher",
        voucher("alpha", &ids[0], "replacement-voucher", NOW + 172800),
    )
    .await
    .unwrap();
    assert!(
        issue_community(&alpha, ah, &a, &passport)
            .await
            .credential
            .is_some()
    );
    assert!(
        !serde_json::from_value::<Available>(
            ac.call("handle_available", json!({"handle":"member_one"}))
                .await
                .unwrap()
        )
        .unwrap()
        .available
    );
    ac.call("passkey_revoke", json!({"credential":a.credential}))
        .await
        .unwrap();
    assert_eq!(
        call_status(&alpha, ah, Some(&a.session), "lobby", json!({})).await,
        401
    );
    alpha.clock.set(NOW + 3 * 366 * 86400);
    alpha.door.maintain().await.unwrap();
    assert!(
        serde_json::from_value::<Available>(
            client(&alpha, ah, None)
                .call("handle_available", json!({"handle":"member_one"}))
                .await
                .unwrap()
        )
        .unwrap()
        .available
    );
    // Accidentally assigning the global database to a community fails migration
    // validation; a process cannot silently acquire the other service's tables.
    let mut overlapping =
        cvld::config::CommunityConfig::read(alpha.dir.path().join("config.json").to_str().unwrap())
            .unwrap();
    overlapping.database_url = format!("file://{}", global.dir.path().join("global.db").display());
    assert!(
        cvld::service::Door::community(overlapping, global.clock.clone())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn community_public_and_expensive_actions_have_aggregate_quotas() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community_with_burst("quota", &public, 1).await;
    let host = "api.quota.example.test";
    for (action, body) in [
        ("handle_available", json!({"handle":"available_one"})),
        ("register_begin", json!({})),
        ("presentation_challenge", json!({})),
    ] {
        assert_ne!(
            call_status(&community, host, None, action, body.clone()).await,
            429
        );
        assert_eq!(call_status(&community, host, None, action, body).await, 429);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn running_community_refreshes_expired_public_global_status() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community("fresh", &public).await;
    let host = "api.fresh.example.test";
    let now = NOW + 3 * 86_400;
    global.clock.set(now);
    community.clock.set(now);
    assert_eq!(
        call_status(&community, host, None, "presentation_challenge", json!({})).await,
        409
    );
    global.door.maintain().await.unwrap();
    let updated: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    std::fs::write(community.dir.path().join("global-status"), updated.status).unwrap();
    community.door.maintain().await.unwrap();
    assert_eq!(
        call_status(&community, host, None, "presentation_challenge", json!({})).await,
        200
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_global_epoch_refresh_refuses_old_proofs_and_durable_rollback() {
    let global = global(100).await;
    let (wallet, passport, public) = wallet_passport(&global).await;
    let community = community("epoch", &public).await;
    let host = "api.epoch.example.test";
    let member = enrol_community(&community, host, &passport).await;
    let old_proof = presentation(&community, host, Some(&member.session), &passport).await;
    let root = enrol(
        &global,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    let root_client = client(&global, ROOT, Some(&root.session));
    root_client
        .call("global_warn", json!({"user":wallet.user}))
        .await
        .unwrap();
    root_client
        .call(
            "global_suspend",
            json!({"user":wallet.user,"until":(NOW/86_400+1)*86_400}),
        )
        .await
        .unwrap();
    let updated: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    std::fs::write(community.dir.path().join("global-status"), &updated.status).unwrap();
    assert_eq!(
        call_status(
            &community,
            host,
            Some(&member.session),
            "credential_issue",
            json!({"presentation":old_proof,"devices":vec![[13u8;32]]})
        )
        .await,
        409
    );
    std::fs::write(community.dir.path().join("global-status"), public.status).unwrap();
    assert_eq!(
        call_status(&community, host, None, "presentation_challenge", json!({})).await,
        409
    );
    let config = cvld::config::CommunityConfig::read(
        community.dir.path().join("config.json").to_str().unwrap(),
    )
    .unwrap();
    assert!(
        cvld::service::Door::community(config, community.clock.clone())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn free_fields_refuse_pins_without_changing_public_member_metadata() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let community = community("seals", &public).await;
    let host = "api.seals.example.test";
    let admin = enrol(
        &community,
        "api.admin.seals.example.test",
        Some("synthetic-admin-enrolment-capability"),
    )
    .await;
    let mut schema = community_schema("seals", 2);
    schema.public[0].change_preset = cplc::cshm::ChangePreset::Free;
    client(
        &community,
        "api.admin.seals.example.test",
        Some(&admin.session),
    )
    .call("schema_set", json!({"schema": schema}))
    .await
    .unwrap();
    let before = client(&community, host, None)
        .call("trust_feed", json!({}))
        .await
        .unwrap();
    let member = enrol_community(&community, host, &passport).await;
    let pseudonym = passport
        .pseudonym(&cpsd::CommunityId::new("seals").unwrap())
        .to_hex();
    let pin = cmty::cmbr::PinV2::seal(
        &cpns::FingerprintContext {
            community: "seals",
            member: &pseudonym,
            field: "restricted",
        },
        b"true",
        &cpns::Salt::from_bytes(vec![17; 32]).unwrap(),
    );
    assert_eq!(
        call_status(
            &community,
            host,
            Some(&member.session),
            "pin_set",
            json!({"field": "restricted", "pin": pin})
        )
        .await,
        400
    );
    let c = client(&community, host, Some(&member.session));
    assert!(
        c.call("pin_get", json!({"field": "restricted"}))
            .await
            .unwrap()["pin"]
            .is_null()
    );
    c.call("handle_reserve", json!({"handle":"member_seals"}))
        .await
        .unwrap();
    c.call(
        "gate_voucher",
        voucher("seals", &pseudonym, "seal-voucher", NOW + 172800),
    )
    .await
    .unwrap();
    assert!(
        issue_community(&community, host, &member, &passport)
            .await
            .credential
            .is_some()
    );
    let after = c.call("trust_feed", json!({})).await.unwrap();
    assert_eq!(before, after);
    for field in [
        "settings",
        "schema",
        "schema_versions",
        "communities",
        "revocations",
        "manifest",
    ] {
        let bytes: Vec<u8> = serde_json::from_value(after[field].clone()).unwrap();
        assert!(
            !bytes
                .windows(pseudonym.len())
                .any(|w| w == pseudonym.as_bytes())
        );
        assert!(
            !bytes
                .windows(member.user.len())
                .any(|w| w == member.user.as_bytes())
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_global_signing_key_cannot_be_installed_as_a_community_key() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let service = community("key-scope", &public).await;
    let config_path = service.dir.path().join("config.json");
    let mut config = cvld::config::CommunityConfig::read(config_path.to_str().unwrap()).unwrap();
    let correct_seed = config.signing_seed_file.clone();
    let fresh_db = format!("file://{}", service.dir.path().join("fresh.db").display());
    config.database_url = fresh_db.clone();
    config.signing_seed_file = global.dir.path().join("signer").to_str().unwrap().into();
    assert!(matches!(
        cvld::service::Door::community(config, service.clock.clone()).await,
        Err(cvld::error::Error::Invalid)
    ));
    // Refusal precedes signer creation, so correcting the configuration works
    // without erasing or resetting any database state.
    let mut corrected = cvld::config::CommunityConfig::read(config_path.to_str().unwrap()).unwrap();
    corrected.database_url = fresh_db;
    corrected.signing_seed_file = correct_seed.clone();
    cvld::service::Door::community(corrected, service.clock.clone())
        .await
        .unwrap();
    let config = cvld::config::CommunityConfig::read(config_path.to_str().unwrap()).unwrap();
    let ring = csgn::KeyRing::from_cbor(&public.key_ring).unwrap();
    let status = ring
        .verify(&public.status, csgn::Kind::SettingsSnapshot, NOW)
        .unwrap();
    let mut shared = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "cglb:global",
        csgn::SecretKey::from_seed(&mut cvld::config::Config::seed(&correct_seed).unwrap()),
        cplc::day(NOW),
        100 * 86_400,
    )
    .await
    .unwrap();
    for retired in [false, true] {
        if retired {
            shared
                .rotate(csgn::SecretKey::from_seed(&mut [4; 32]), NOW)
                .await
                .unwrap();
        }
        let signed = shared
            .sign(
                csgn::Kind::SettingsSnapshot,
                status.payload(),
                NOW,
                status.valid_until(),
            )
            .await
            .unwrap();
        std::fs::write(&config.global_status_file, signed).unwrap();
        std::fs::write(
            &config.global_key_ring_file,
            shared.key_ring().unwrap().to_cbor(),
        )
        .unwrap();
        assert!(matches!(
            cvld::service::Door::community(
                cvld::config::CommunityConfig::read(config_path.to_str().unwrap()).unwrap(),
                service.clock.clone()
            )
            .await,
            Err(cvld::error::Error::Invalid)
        ));
        assert_eq!(
            call_status(
                &service,
                "api.key-scope.example.test",
                None,
                "presentation_challenge",
                json!({})
            )
            .await,
            400
        );
    }
}
