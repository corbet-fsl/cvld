//! Real HTTP router, original Keyhole/signers/Store and explicit development
//! passport fixture. This does not qualify pinned TLS, hardware, G3 or Tor.
use super::*;
use crate::test_support as support;
use serde_json::json;
use std::sync::atomic::AtomicU64;
use support::{NOW, Running, WALLET};
use tower::ServiceExt;
use webauthn_authenticator_rs::AuthenticatorBackend;

async fn running() -> Running {
    let dir = tempfile::tempdir().unwrap();
    let mut config = support::global_config(dir.path(), 1000).await;
    let mut rules = cmty::cplc::crbk::Rulebook::default();
    rules
        .define(
            "quota",
            cmty::cplc::crbk::Setting {
                value_type: cmty::cplc::crbk::SettingType::Integer,
                nullable: false,
                default: json!(17),
                bounds: cmty::cplc::crbk::Bounds {
                    min: Some(0.into()),
                    max: Some(100.into()),
                },
                lowest_layer: cmty::cplc::crbk::Layer::Community,
                kind: cmty::cplc::crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    let schema = serde_json::from_value(json!({"community":"wallet","version":1,
        "public":[{"id":"consent","label":"Receive invitations?","kind":{"type":"yes_no"},
            "required":true,"filterable":false,"change_preset":"stable","no_contact_details":false}],"private":[]})).unwrap();
    let publication = cgbl::WalletPublicationConfig::new(
        WALLET,
        &format!("https://vault.{WALLET}"),
        rules,
        cmty::cplc::SchemaVersions {
            purpose: cmty::cplc::SchemaVersionsPurpose::SchemaVersionsV1,
            current: 1,
            versions: vec![cmty::cplc::SchemaVersion {
                schema,
                changes: None,
            }],
        },
        std::collections::BTreeSet::new(),
        2 * 86_400,
    )
    .unwrap();
    let seed = dir.path().join("wallet-seed");
    std::fs::write(&seed, [47; 32]).unwrap();
    let settings = dir.path().join("wallet-publication.json");
    std::fs::write(&settings, serde_json::to_vec(&publication).unwrap()).unwrap();
    config.wallet = Some(crate::config::WalletConfig {
        signing_seed_file: seed.to_str().unwrap().into(),
        publication_file: settings.to_str().unwrap().into(),
        signer_max_seconds: 100 * 86_400,
        stamp_key_file: None,
        stamp_limit: None,
        stamp_period_seconds: None,
    });
    let clock = Arc::new(support::TestClock(AtomicU64::new(NOW)));
    let door = Door::global(config, clock.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = crate::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Running {
        base,
        door,
        clock,
        task,
        dir,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_wallet_http_certificate_and_feed_keep_passport_issuer_and_private_uuid_separate() {
    let f = running().await;
    let mut member = support::enrol(&f, WALLET, None).await;
    let client = support::client(&f, WALLET, Some(&member.session));
    let device = [49; 32];
    let body = support::proven(
        &f,
        WALLET,
        &member.session,
        &mut member.authenticator,
        json!({"kind":"device_authorize","key":device}),
        json!({"key":device}),
    )
    .await;
    let observed: DeviceKeys =
        serde_json::from_value(client.call("wallet_device_authorize", body).await.unwrap())
            .unwrap();
    assert_eq!(observed.keys, vec![device]);
    let feed: TrustFeed =
        serde_json::from_value(client.call("wallet_trust_feed", json!({})).await.unwrap()).unwrap();
    let wallet_ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    assert_eq!(wallet_ring.issuer(), "wallet");
    let passport: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    assert_eq!(
        csgn::KeyRing::from_cbor(&passport.key_ring)
            .unwrap()
            .issuer(),
        "cgbl:global"
    );
    let certificate: PasskeyCertificateResponse =
        serde_json::from_value(client.call("passkey_certificate", json!({})).await.unwrap())
            .unwrap();
    assert_eq!(certificate.checked_at, NOW);
    let verified =
        ckyh::certificate::verify(&wallet_ring, &certificate.bytes, &member.user, NOW).unwrap();
    assert_eq!(verified.credential_id(), member.credential);
    assert!(
        ckyh::certificate::verify(
            &csgn::KeyRing::from_cbor(&passport.key_ring).unwrap(),
            &certificate.bytes,
            &member.user,
            NOW
        )
        .is_err()
    );
    let revocations = wallet_ring
        .verify(&feed.revocations, csgn::Kind::RevocationListSnapshot, NOW)
        .unwrap();
    assert!(!String::from_utf8_lossy(revocations.payload()).contains(&member.user));
    let empty = support::global(1000).await;
    let other = support::enrol(&empty, WALLET, None).await;
    assert_eq!(
        support::call_status(
            &empty,
            WALLET,
            Some(&other.session),
            "passkey_certificate",
            json!({})
        )
        .await,
        403
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn original_uv_self_ban_publishes_wallet_key_and_device_revocations_without_new_authority() {
    let f = running().await;
    let mut member = support::enrol(&f, WALLET, None).await;
    let client = support::client(&f, WALLET, Some(&member.session));
    let body = support::proven(
        &f,
        WALLET,
        &member.session,
        &mut member.authenticator,
        json!({"kind":"device_authorize","key":vec![49;32]}),
        json!({"key":vec![49;32]}),
    )
    .await;
    client.call("wallet_device_authorize", body).await.unwrap();
    let begin: SelfBanChallenge = serde_json::from_value(
        client
            .call("global_self_ban_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let request: ckyh::RequestChallengeResponse = serde_json::from_value(begin.options).unwrap();
    let credential = member
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&format!("https://vault.{WALLET}")).unwrap(),
            request.public_key,
            300_000,
        )
        .unwrap();
    client
        .call(
            "global_self_ban_finish",
            json!({"ceremony":begin.ceremony,"credential":credential}),
        )
        .await
        .unwrap();
    assert_eq!(
        support::call_status(
            &f,
            WALLET,
            Some(&member.session),
            "passkey_certificate",
            json!({})
        )
        .await,
        401
    );
    let feed: TrustFeed =
        serde_json::from_value(client.call("wallet_trust_feed", json!({})).await.unwrap()).unwrap();
    let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    let signed = ring
        .verify(&feed.revocations, csgn::Kind::RevocationListSnapshot, NOW)
        .unwrap();
    let snapshot: cmty::cplc::Snapshot<cmty::cplc::Revocations> =
        serde_json::from_slice(signed.payload()).unwrap();
    assert!(snapshot.content.members.is_empty());
    assert!(snapshot.content.devices.contains(&[49; 32]));
    assert!(snapshot.content.passkeys.contains(&member.credential));
}

struct Release(Arc<crate::auth::wallet::WorkerGate>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn cancelled_real_http_sdk_worker_blocks_publication_and_original_total_shutdown_join() {
    for after in [false, true] {
        let f = running().await;
        let mut member = support::enrol(&f, WALLET, None).await;
        let proof = support::step_up(
            &f,
            WALLET,
            &member.session,
            &mut member.authenticator,
            json!({"kind":"passkey_revoke","credential":member.credential}),
        )
        .await;
        let gate = crate::auth::wallet::WorkerGate::new(after);
        let _release_on_failure = Release(gate.clone());
        f.door.auth(WALLET).unwrap().lock().await.wallet_worker_gate = Some(gate.clone());
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/passkey_revoke")
            .header("host", WALLET)
            .header("authorization", format!("Bearer {}", member.session))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&json!({"credential":member.credential,"step_up":proof}))
                    .unwrap(),
            ))
            .unwrap();
        let mut pending = Box::pin(crate::api::router(f.door.clone()).oneshot(request));
        tokio::select! {
            _ = gate.arrived.notified() => (),
            result = &mut pending => panic!("real SDK worker did not suspend: {}",result.is_ok()),
        }
        drop(pending); // Actual HTTP dispatcher cancellation; worker continues.
        let client = support::client(&f, WALLET, None);
        let mut feed = Box::pin(client.call("wallet_trust_feed", json!({})));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut feed)
                .await
                .is_err()
        );
        drop(feed);
        f.door.begin_shutdown_accounts().unwrap();
        let mut joined = Box::pin(f.door.shutdown_accounts());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut joined)
                .await
                .is_err()
        );
        gate.release();
        tokio::time::timeout(Duration::from_secs(2), &mut joined)
            .await
            .unwrap()
            .unwrap();
        // Definitive original SDK completion survives the lost HTTP reply.
        let keys = f.door.auth(WALLET).unwrap().lock().await.passkeys.clone();
        let user = ckyh::Uuid::parse_str(&member.user).unwrap();
        let credential = member.credential.clone();
        let records = tokio::task::spawn_blocking(move || keys.list(user))
            .await
            .unwrap()
            .unwrap();
        assert!(
            records.iter().any(
                |key| key.credential_id().as_ref() == credential.as_slice() && key.is_revoked()
            )
        );
        assert!(
            support::client(&f, WALLET, None)
                .call("wallet_trust_feed", json!({}))
                .await
                .is_err()
        );
    }
}
