#![cfg(feature = "development-gate")]
//! Real HTTP registration/renewal and Keyhole verification under the service's
//! published ring. Current Charter/Envoy revocation verification belongs to its
//! consumer fixtures; signature validity alone is deliberately not that verdict.
mod support;

use cmty::cplc;
use cvld::api::*;
use serde_json::json;
use support::*;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

async fn feed(service: &Running, host: &str) -> TrustFeed {
    serde_json::from_value(
        client(service, host, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn lobby(service: &Running, host: &str, session: &str) -> Lobby {
    serde_json::from_value(
        client(service, host, Some(session))
            .call("lobby", json!({}))
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn renew(service: &Running, host: &str, session: &str) -> Vec<u8> {
    let response: Bytes = serde_json::from_value(
        client(service, host, Some(session))
            .call("passkey_certificate", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    response.bytes
}

fn assertion(
    authenticator: &mut SoftToken,
    host: &str,
    request: ckyh::RequestChallengeResponse,
) -> ckyh::lineage::Assertion {
    let response: ckyh::PublicKeyCredential = authenticator
        .perform_auth(
            ckyh::Url::parse(&format!("https://{host}")).unwrap(),
            request.public_key,
            300_000,
        )
        .unwrap()
        .into();
    ckyh::lineage::Assertion {
        credential_id: response.raw_id.as_ref().to_vec(),
        client_data_json: response.response.client_data_json.as_ref().to_vec(),
        authenticator_data: response.response.authenticator_data.as_ref().to_vec(),
        signature: response.response.signature.as_ref().to_vec(),
        user_handle: response
            .response
            .user_handle
            .as_ref()
            .map(|handle| handle.as_ref().to_vec()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_and_authenticated_renewal_use_the_published_community_ring() {
    let global = global(100).await;
    let (wallet, passport, public) = wallet_passport(&global).await;
    assert!(wallet.certificate.is_none());
    let alpha = community("alpha", &public).await;
    let beta = community("beta", &public).await;
    let ah = "api.alpha.example.test";
    let bh = "api.beta.example.test";
    let before = feed(&alpha, ah).await;
    let mut member = enrol_community(&alpha, ah, &passport).await;
    let other = enrol_community(&beta, bh, &passport).await;
    let own = lobby(&alpha, ah, &member.session).await;
    let foreign = lobby(&beta, bh, &other.session).await;
    assert_ne!(own.member_id, foreign.member_id);
    assert_ne!(own.member_id, member.user);

    let ring = csgn::KeyRing::from_cbor(&before.key_ring).unwrap();
    let foreign_ring = csgn::KeyRing::from_cbor(&feed(&beta, bh).await.key_ring).unwrap();
    let bytes = member.certificate.as_ref().unwrap();
    let certificate = ckyh::certificate::verify(&ring, bytes, &own.member_id, NOW).unwrap();
    assert_eq!(certificate.credential_id(), member.credential);
    assert_eq!(certificate.member(), own.member_id);
    assert_eq!(certificate.signed_bytes(), bytes);
    let payload = ring.verify(bytes, csgn::Kind::Credential, NOW).unwrap();
    assert!(!String::from_utf8_lossy(payload.payload()).contains(&member.user));

    let challenge = [71; 32];
    let witness = assertion(
        &mut member.authenticator,
        ah,
        certificate.request(challenge, NOW).unwrap(),
    );
    certificate.assertion(&witness, challenge, NOW).unwrap();
    assert!(certificate.assertion(&witness, [72; 32], NOW).is_err());
    assert!(ckyh::certificate::verify(&ring, bytes, &foreign.member_id, NOW).is_err());
    assert!(ckyh::certificate::verify(&ring, bytes, &member.user, NOW).is_err());
    assert!(ckyh::certificate::verify(&foreign_ring, bytes, &own.member_id, NOW).is_err());

    let renewed = renew(&alpha, ah, &member.session).await;
    let renewed = ckyh::certificate::verify(&ring, &renewed, &own.member_id, NOW).unwrap();
    assert_eq!(renewed.credential_id(), certificate.credential_id());
    assert_eq!(renewed.issued_at(), certificate.issued_at());
    renewed.assertion(&witness, challenge, NOW).unwrap();
    // Registration and renewal publish no member-activity revision or timestamp.
    assert_eq!(
        serde_json::to_value(feed(&alpha, ah).await).unwrap(),
        serde_json::to_value(&before).unwrap()
    );

    assert_eq!(
        call_status(&alpha, ah, None, "passkey_certificate", json!({})).await,
        401
    );
    assert_eq!(
        call_status(
            &alpha,
            ah,
            Some(&other.session),
            "passkey_certificate",
            json!({})
        )
        .await,
        401
    );
    assert_eq!(
        call_status(
            &global,
            WALLET,
            Some(&wallet.session),
            "passkey_certificate",
            json!({})
        )
        .await,
        421
    );
    // Renewal derives both identity and credential from the authenticated session.
    for body in [
        json!({"member":foreign.member_id}),
        json!({"credential":other.credential}),
    ] {
        assert_eq!(
            call_status(
                &alpha,
                ah,
                Some(&member.session),
                "passkey_certificate",
                body
            )
            .await,
            400
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_refuses_renewal_and_retains_the_other_registered_key() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let host = "api.alpha.example.test";
    let member = enrol_community(&service, host, &passport).await;
    let own = lobby(&service, host, &member.session).await;
    let member_client = client(&service, host, Some(&member.session));
    let begin: AddedPasskey = serde_json::from_value(
        member_client
            .call("passkey_add", json!({"step":"begin"}))
            .await
            .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Challenge {
        ceremony, options, ..
    } = begin
    else {
        panic!("expected actual additional-registration challenge")
    };
    let mut second = SoftToken::new(true).unwrap().0;
    let request: ckyh::CreationChallengeResponse = serde_json::from_value(options).unwrap();
    let mut request = request.public_key;
    // The existing SoftToken fixture supports UV but not resident registration.
    request
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let registration = second
        .perform_register(
            ckyh::Url::parse(&format!("https://{host}")).unwrap(),
            request,
            300_000,
        )
        .unwrap();
    let expected_credential = registration.raw_id.as_ref().to_vec();
    let added: AddedPasskey = serde_json::from_value(
        member_client
            .call(
                "passkey_add",
                json!({"step":"finish","ceremony":ceremony,"credential":registration}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Registered {
        user,
        credential,
        certificate,
    } = added
    else {
        panic!("expected actual additional-registration certificate")
    };
    assert_eq!(user, member.user);
    assert_eq!(credential, expected_credential);
    assert_ne!(credential, member.credential);
    let before = feed(&service, host).await;
    let ring = csgn::KeyRing::from_cbor(&before.key_ring).unwrap();
    let added_certificate =
        ckyh::certificate::verify(&ring, &certificate, &own.member_id, NOW).unwrap();
    assert_eq!(added_certificate.credential_id(), credential);
    let challenge = [73; 32];
    let witness = assertion(
        &mut second,
        host,
        added_certificate.request(challenge, NOW).unwrap(),
    );
    added_certificate
        .assertion(&witness, challenge, NOW)
        .unwrap();
    let second_session = login(&service, host, &mut second, &user, &credential).await;
    let second_client = client(&service, host, Some(&second_session));
    second_client
        .call("passkey_revoke", json!({"credential":member.credential}))
        .await
        .unwrap();

    assert_eq!(
        call_status(
            &service,
            host,
            Some(&member.session),
            "passkey_certificate",
            json!({})
        )
        .await,
        401
    );
    let after = feed(&service, host).await;
    let current_ring = csgn::KeyRing::from_cbor(&after.key_ring).unwrap();
    let revocations: cplc::Snapshot<cplc::Revocations> = cplc::verify_snapshot(
        &current_ring,
        &after.revocations,
        cplc::SnapshotExpectation {
            community: "alpha",
            kind: cplc::SnapshotKind::RevocationList,
            minimum_revision: 1,
            policy_epoch: after.policy_epoch,
            now: NOW,
        },
    )
    .unwrap();
    assert!(revocations.content.passkeys.contains(&member.credential));
    assert!(!revocations.content.passkeys.contains(&credential));
    // Old signatures remain mathematical signatures. Consumers must install the
    // current Charter revocations; this test never turns them into live authority.
    assert!(
        ckyh::certificate::verify(
            &current_ring,
            member.certificate.as_ref().unwrap(),
            &own.member_id,
            NOW,
        )
        .is_ok()
    );
    let renewed = renew(&service, host, &second_session).await;
    let renewed = ckyh::certificate::verify(&current_ring, &renewed, &own.member_id, NOW).unwrap();
    assert_eq!(renewed.credential_id(), credential);
    renewed.assertion(&witness, challenge, NOW).unwrap();

    second_client.call("logout", json!({})).await.unwrap();
    assert_eq!(
        call_status(
            &service,
            host,
            Some(&second_session),
            "passkey_certificate",
            json!({})
        )
        .await,
        401
    );
}

mod awaited_registration_clock {
    use super::*;
    use cmty::cmbr;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };

    // Observe the real clock without changing its answers or owner control flow.
    struct MembershipClock {
        time: Arc<TestClock>,
        observed: Arc<AtomicBool>,
    }
    impl clbs::Clock for MembershipClock {
        fn now(&self) -> clbs::Result<i64> {
            self.observed.store(true, Ordering::SeqCst);
            self.time
                .0
                .load(Ordering::SeqCst)
                .try_into()
                .map_err(|_| clbs::Error::Denied)
        }
    }

    // As in the service's unconfigured authority, no legal order can be accepted.
    struct UnconfiguredLegalAuthority;
    impl clbs::Verifier for UnconfiguredLegalAuthority {
        async fn verify_legal(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
            Err(clbs::Error::Denied)
        }
        async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
            Err(clbs::Error::Denied)
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn first_certificate_refuses_clock_regression_during_real_registration_storage_await() {
        // This tests Membership's certificate preparation boundary. HTTP sessions,
        // Policy signing and current Charter authority are covered separately.
        for regress in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut config = crlt::Config::new(
                format!("file://{}", dir.path().join("members.db").display()),
                "",
            );
            config.max_connections = 1;
            let db = crlt::Db::open(config).await.unwrap();
            let mut schemas = cmbr::SCHEMAS.to_vec();
            schemas.push(("cmbr-device-keys", cmbr::DEVICE_KEYS_SCHEMA));
            let migrations: Vec<_> = schemas
                .iter()
                .enumerate()
                .map(|(i, (name, sql))| crlt::Migration::new(i as u32 + 1, name, sql))
                .collect();
            db.migrate(&migrations).await.unwrap();
            let time = Arc::new(TestClock(AtomicU64::new(NOW)));
            let observed = Arc::new(AtomicBool::new(false));
            let host = "api.alpha.example.test";
            let origin = ckyh::Url::parse(&format!("https://{host}")).unwrap();
            let membership = cmbr::Membership::new(
                &db,
                cmbr::LibsqlStorage::new(&db, "alpha").unwrap(),
                cmbr::Config {
                    pending_days: 2,
                    lease_months: 1,
                    membership_action: "membership".into(),
                    release_period: Default::default(),
                    rp_id: host.into(),
                    origins: vec![origin.clone()],
                },
                UnconfiguredLegalAuthority,
                MembershipClock {
                    time: time.clone(),
                    observed: observed.clone(),
                },
            )
            .unwrap();
            let user = ckyh::Uuid::new_v4();
            let member = "01".repeat(48);
            let (mut options, pending) =
                membership.begin_registration(user, &member).await.unwrap();
            options
                .public_key
                .authenticator_selection
                .as_mut()
                .unwrap()
                .require_resident_key = false;
            let mut authenticator = SoftToken::new(true).unwrap().0;
            let response = authenticator
                .perform_register(origin.clone(), options.public_key, 300_000)
                .unwrap();
            let credential = response.raw_id.as_ref().to_vec();

            // The original transaction holds the sole pool lease. The first
            // registration read must await its release; no stored result is faked.
            let blocker = db.tx("alpha").await.unwrap();
            observed.store(false, Ordering::SeqCst);
            let mut attempt =
                std::pin::pin!(membership.finish_registration_certified(pending, response.into()));
            assert!(futures_util::poll!(attempt.as_mut()).is_pending());
            assert!(observed.load(Ordering::SeqCst));
            if regress {
                // Same day: coarse signing timestamps cannot catch this regression.
                time.set(NOW - 1);
            }
            blocker.rollback().await.unwrap();
            let result = tokio::time::timeout(std::time::Duration::from_secs(30), attempt)
                .await
                .expect("real registration did not resume after releasing storage");
            if regress {
                assert!(matches!(result, Err(cmbr::Error::Identity)));
            } else {
                let registered = result.unwrap();
                assert_eq!(registered.certificate().member(), member);
                assert_eq!(registered.certificate().credential_id(), credential);
                drop(registered);
            }

            // The passkey was genuinely committed before certificate refusal.
            // A fresh real authentication recovers certificate preparation after
            // the clock is restored; it never repeats registration or trusts a flag.
            time.set(NOW);
            let (request, pending) = membership
                .begin_login(user, credential.clone().into())
                .await
                .unwrap();
            let response = authenticator
                .perform_auth(origin, request.public_key, 300_000)
                .unwrap();
            let login = membership
                .finish_login(pending, response.into())
                .await
                .unwrap();
            let recovered = membership
                .passkey_certificate(&login.authentication)
                .await
                .unwrap();
            assert_eq!(recovered.certificate().member(), member);
            assert_eq!(recovered.certificate().credential_id(), credential);
        }
    }
}
