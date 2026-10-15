//! Real UV resident passkeys and HTTP prove the permanent holder-only intent.
#![cfg(feature = "development-gate")]
mod support;
use cvld::api::*;
use cvld::service::Clock;
use serde_json::json;
use support::{
    resident::strip_prf,
    self_ban::{Wallet, confirmation, discover, wallet},
    *,
};

async fn public(service: &Running) -> GlobalPublic {
    serde_json::from_value(
        client(service, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap()
}
fn status(public: &GlobalPublic) -> cgbl::Status {
    cgbl::Status::verify(
        &public.status,
        &csgn::KeyRing::from_cbor(&public.key_ring).unwrap(),
        "global",
        1,
        1,
        NOW,
    )
    .unwrap()
}
async fn passport(service: &Running, owner: &Wallet) -> cpsd::Passport {
    let api = client(service, WALLET, Some(&owner.session.token));
    api.call("development_gate", json!({})).await.unwrap();
    let public = public(service).await;
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut rng = cpsd::rand::rngs::OsRng;
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let challenge: Bytes =
        serde_json::from_value(api.call("passport_challenge", json!({})).await.unwrap()).unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let (request, pending) = cpsd::request_issue(&mut rng, &secret, &issuer, &challenge).unwrap();
    let reply: Bytes = serde_json::from_value(
        api.call(
            "passport_issue",
            json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes()}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    pending
        .finish(&cpsd::BlindPassport::from_bytes(&reply.bytes).unwrap())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permanent_self_ban_requires_the_exact_holder_session_and_invalidates_the_passport_epoch() {
    let service = global(200).await;
    let mut owner = wallet(&service, WALLET, None).await;
    let passport = passport(&service, &owner).await;
    let alternate = discover(&service, WALLET, &mut owner.device).await;
    let stranger = wallet(&service, WALLET, None).await;
    let root = wallet(
        &service,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    let before = public(&service).await;
    let before_status = status(&before);
    assert_eq!(
        call_status(&service, WALLET, None, "global_self_ban_begin", json!({})).await,
        401
    );
    assert_eq!(
        call_status(
            &service,
            ROOT,
            Some(&root.session.token),
            "global_self_ban_begin",
            json!({})
        )
        .await,
        403
    );
    let body = confirmation(&service, &mut owner).await;
    for (host, token) in [
        (WALLET, Some(alternate.token.as_str())),
        (WALLET, Some(stranger.session.token.as_str())),
        (ROOT, Some(owner.session.token.as_str())),
        (WALLET, None),
    ] {
        assert_eq!(
            call_status(
                &service,
                host,
                token,
                "global_self_ban_finish",
                body.clone()
            )
            .await,
            401
        );
    }
    let mut wrong_intent = body.clone();
    wrong_intent["reason"] = json!("legal");
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&owner.session.token),
            "global_self_ban_finish",
            wrong_intent
        )
        .await,
        400
    );
    assert_eq!(status(&public(&service).await).epoch, before_status.epoch);
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&owner.session.token),
            "global_self_ban_finish",
            body.clone()
        )
        .await,
        200
    );
    let after = public(&service).await;
    let after_status = status(&after);
    assert_eq!(after_status.epoch, before_status.epoch + 1);
    assert_eq!(after_status.policy_revision, before_status.policy_revision);
    for token in [&owner.session.token, &alternate.token] {
        assert_eq!(
            call_status(&service, WALLET, Some(token), "passkey_list", json!({})).await,
            401
        );
    }
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&owner.session.token),
            "global_self_ban_finish",
            body
        )
        .await,
        401
    );
    // A valid old passport cannot generate the now-required epoch's proof.
    let mut rng = cpsd::rand::rngs::OsRng;
    let request = cpsd::PresentationRequest::for_epoch(
        &mut rng,
        cpsd::CommunityId::new(b"self-ban-consumer").unwrap(),
        after_status.epoch,
        [cpsd::GateId::new("development").unwrap()],
        NOW,
        after_status.shared_expiry,
    )
    .unwrap();
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "self-ban-consumer",
        csgn::SecretKey::from_seed(&mut [8; 32]),
        NOW - 1,
        86400,
    )
    .await
    .unwrap();
    let signed = signer
        .sign(csgn::Kind::Credential, &request.to_bytes(), NOW, NOW + 1)
        .await
        .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        request.community().clone(),
        signer.key_ring().unwrap().clone(),
    );
    assert!(passport.present(&mut rng, &expected, &signed, NOW).is_err());
    owner.session = discover(&service, WALLET, &mut owner.device).await;
    for action in ["development_gate", "passport_challenge"] {
        assert_eq!(
            call_status(
                &service,
                WALLET,
                Some(&owner.session.token),
                action,
                json!({})
            )
            .await,
            409
        );
    }
    assert_eq!(status(&public(&service).await).epoch, after_status.epoch);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wallet_can_self_ban_before_any_gate_without_blocking_a_different_wallet() {
    let service = global(200).await;
    let mut owner = wallet(&service, WALLET, None).await;
    let before = status(&public(&service).await);
    let body = confirmation(&service, &mut owner).await;
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&owner.session.token),
            "global_self_ban_finish",
            body
        )
        .await,
        200
    );
    assert_eq!(status(&public(&service).await).epoch, before.epoch + 1);
    owner.session = discover(&service, WALLET, &mut owner.device).await;
    for action in ["development_gate", "passport_challenge"] {
        assert_eq!(
            call_status(
                &service,
                WALLET,
                Some(&owner.session.token),
                action,
                json!({})
            )
            .await,
            409
        );
    }
    let fresh = wallet(&service, WALLET, None).await;
    client(&service, WALLET, Some(&fresh.session.token))
        .call("development_gate", json!({}))
        .await
        .unwrap();
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&fresh.session.token),
            "passport_challenge",
            json!({})
        )
        .await,
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_login_assertion_expired_intent_logout_and_revocation_never_block() {
    for cause in ["login-proof", "expiry", "logout", "revocation"] {
        let service = global(200).await;
        let mut owner = wallet(&service, WALLET, None).await;
        client(&service, WALLET, Some(&owner.session.token))
            .call("development_gate", json!({}))
            .await
            .unwrap();
        let before = status(&public(&service).await).epoch;
        if cause == "revocation" {
            assert_eq!(
                call_status(
                    &service,
                    WALLET,
                    None,
                    "login_begin",
                    json!({"user":owner.session.user,"credential":owner.credential})
                )
                .await,
                200
            );
        }
        let mut body = confirmation(&service, &mut owner).await;
        match cause {
            "login-proof" => {
                let begin: DiscoverableCeremony = serde_json::from_value(
                    client(&service, WALLET, None)
                        .call("login_discoverable_begin", json!({}))
                        .await
                        .unwrap(),
                )
                .unwrap();
                let mut credential = owner
                    .device
                    .ceremony(begin.options, false, &format!("https://vault.{WALLET}"))
                    .await;
                strip_prf(&mut credential);
                body["credential"] = credential;
            }
            "expiry" => service.clock.set(NOW + 300),
            "logout" => {
                client(&service, WALLET, Some(&owner.session.token))
                    .call("logout", json!({}))
                    .await
                    .unwrap();
            }
            "revocation" => {
                let login = json!({"user":owner.session.user,"credential":owner.credential});
                // Revoking the authorizing key commits, then ends its session;
                // the session that ended itself is answered with success.
                let proof = owner
                    .device
                    .step_up(
                        &service,
                        WALLET,
                        &owner.session.token,
                        json!({"kind":"passkey_revoke","credential":owner.credential}),
                    )
                    .await;
                client(&service, WALLET, Some(&owner.session.token))
                    .call(
                        "passkey_revoke",
                        json!({"credential":owner.credential,"step_up":proof}),
                    )
                    .await
                    .unwrap();
                // Beginning a login is not an oracle for key status: the revoked
                // key still receives a challenge and the refusal belongs at finish.
                let begin: Ceremony = serde_json::from_value(
                    client(&service, WALLET, None)
                        .call("login_begin", login)
                        .await
                        .unwrap(),
                )
                .unwrap();
                let mut credential = owner
                    .device
                    .ceremony(begin.options, false, &format!("https://vault.{WALLET}"))
                    .await;
                strip_prf(&mut credential);
                assert_eq!(
                    call_status(
                        &service,
                        WALLET,
                        None,
                        "login_finish",
                        json!({"ceremony":begin.ceremony,"credential":credential})
                    )
                    .await,
                    401
                );
                assert_eq!(
                    call_status(
                        &service,
                        WALLET,
                        Some(&owner.session.token),
                        "passkey_list",
                        json!({})
                    )
                    .await,
                    401
                );
            }
            _ => unreachable!(),
        }
        assert_eq!(
            call_status(
                &service,
                WALLET,
                Some(&owner.session.token),
                "global_self_ban_finish",
                body
            )
            .await,
            401,
            "{cause}"
        );
        let after = public(&service).await;
        let signed = cgbl::Status::verify(
            &after.status,
            &csgn::KeyRing::from_cbor(&after.key_ring).unwrap(),
            "global",
            1,
            1,
            service.clock.now(),
        )
        .unwrap();
        assert_eq!(signed.epoch, before, "{cause}");
    }
}
