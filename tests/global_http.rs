#![cfg(feature = "development-gate")]
mod support;
use cvld::api::*;
use serde_json::json;
use support::*;

#[tokio::test(flavor = "multi_thread")]
async fn wallet_passkey_blind_passport_and_host_role_boundaries() {
    let service = global(100).await;
    let mut member = enrol(&service, WALLET, None).await;
    let client = client(&service, WALLET, Some(&member.session));
    client.call("development_gate", json!({})).await.unwrap();
    let public: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let ring = csgn::KeyRing::from_cbor(&public.key_ring).unwrap();
    let signed = ring
        .verify(&public.status, csgn::Kind::SettingsSnapshot, NOW)
        .unwrap();
    let status: cglb::Status = serde_json::from_slice(signed.payload()).unwrap();
    assert_eq!(status.epoch, 1);
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut rng = cpsd::rand::rngs::OsRng;
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let challenge: Bytes =
        serde_json::from_value(client.call("passport_challenge", json!({})).await.unwrap())
            .unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let (request, pending) = cpsd::request_issue(&mut rng, &secret, &issuer, &challenge).unwrap();
    let body = json!({"challenge":challenge.to_bytes().to_vec(), "request":request.to_bytes()});
    let other_session = login(
        &service,
        WALLET,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&other_session),
            "passport_issue",
            body.clone()
        )
        .await,
        409
    );
    let issued: Bytes =
        serde_json::from_value(client.call("passport_issue", body.clone()).await.unwrap()).unwrap();
    let passport = pending
        .finish(&cpsd::BlindPassport::from_bytes(&issued.bytes).unwrap())
        .unwrap();
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "passport_issue",
            body
        )
        .await,
        409
    );
    let mut pseudonyms = Vec::new();
    for name in ["community-a", "community-b"] {
        let request = cpsd::PresentationRequest::for_epoch(
            &mut rng,
            cpsd::CommunityId::new(name.as_bytes()).unwrap(),
            1,
            [cpsd::GateId::new("development").unwrap()],
            NOW,
            status.shared_expiry,
        )
        .unwrap();
        let proof = trusted_presentation(&passport, &request).await;
        pseudonyms
            .push(cpsd::verify(&mut rng, std::slice::from_ref(&issuer), &request, &proof).unwrap());
    }
    assert_ne!(pseudonyms[0], pseudonyms[1]);
    assert_eq!(
        call_status(
            &service,
            ROOT,
            Some(&member.session),
            "global_warn",
            json!({"user":member.user})
        )
        .await,
        401
    );
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "global_warn",
            json!({"user":member.user})
        )
        .await,
        403
    );
    assert_eq!(
        call_status(
            &service,
            "api.community-a.example.test",
            Some(&member.session),
            "passport_challenge",
            json!({})
        )
        .await,
        421
    );
    assert_eq!(
        call_status(&service, WALLET, None, "passport_challenge", json!({})).await,
        401
    );
    let root = enrol(
        &service,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    let root_client = support::client(&service, ROOT, Some(&root.session));
    assert!(
        root_client
            .call(
                "global_suspend",
                json!({"user":member.user,"until":(NOW / 86400 + 1) * 86400})
            )
            .await
            .is_err()
    );
    root_client
        .call("global_warn", json!({"user":member.user}))
        .await
        .unwrap();
    root_client
        .call(
            "global_suspend",
            json!({"user":member.user,"until":(NOW / 86400 + 1) * 86400}),
        )
        .await
        .unwrap();
    let changed: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let signed = ring
        .verify(&changed.status, csgn::Kind::SettingsSnapshot, NOW)
        .unwrap();
    let changed: cglb::Status = serde_json::from_slice(signed.payload()).unwrap();
    assert_eq!(changed.epoch, 2);
    assert!(client.call("passport_challenge", json!({})).await.is_err());
    root_client.call("logout", json!({})).await.unwrap();
    assert_eq!(
        call_status(
            &service,
            ROOT,
            Some(&root.session),
            "global_warn",
            json!({"user":member.user})
        )
        .await,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn throttle_is_aggregate_and_sessions_expire() {
    let service = global(2).await;
    assert_eq!(
        call_status(&service, WALLET, None, "global_public", json!({})).await,
        200
    );
    assert_eq!(
        call_status(&service, WALLET, None, "global_public", json!({})).await,
        200
    );
    assert_eq!(
        call_status(&service, WALLET, None, "global_public", json!({})).await,
        429
    );
    let member = enrol(&service, WALLET, None).await;
    service.clock.set(NOW + 601);
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "passport_challenge",
            json!({})
        )
        .await,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_requires_user_verification_and_ceremonies_are_single_use() {
    use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};
    let service = global(30).await;
    let client = client(&service, WALLET, None);
    let start: Ceremony =
        serde_json::from_value(client.call("register_begin", json!({})).await.unwrap()).unwrap();
    let mut challenge: ckyh::CreationChallengeResponse =
        serde_json::from_value(start.options).unwrap();
    // A hostile client weakens the browser option. The server's pending policy remains Required.
    let mut wire = serde_json::to_value(&challenge).unwrap();
    wire["publicKey"]["authenticatorSelection"]["userVerification"] = json!("discouraged");
    challenge = serde_json::from_value(wire).unwrap();
    let mut authenticator = SoftToken::new(false).unwrap().0;
    let credential = authenticator
        .perform_register(
            ckyh::Url::parse(&format!("https://{WALLET}")).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
                let mut options = challenge.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();
    let request = json!({"ceremony":start.ceremony,"credential":credential});
    assert_eq!(
        call_status(&service, WALLET, None, "register_finish", request.clone()).await,
        409
    );
    assert_eq!(
        call_status(&service, WALLET, None, "register_finish", request).await,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_signature_without_uv_cannot_create_a_session() {
    use webauthn_authenticator_rs::AuthenticatorBackend;
    let service = global(50).await;
    let mut member = enrol(&service, WALLET, None).await;
    let client = client(&service, WALLET, None);
    let begin: Ceremony = serde_json::from_value(
        client
            .call(
                "login_begin",
                json!({"user": member.user,"credential":member.credential}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let mut options = begin.options;
    options["publicKey"]["userVerification"] = json!("discouraged");
    let challenge: ckyh::RequestChallengeResponse = serde_json::from_value(options).unwrap();
    let credential = member
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&format!("https://{WALLET}")).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    let body = json!({"ceremony":begin.ceremony,"credential":credential});
    assert_eq!(
        call_status(&service, WALLET, None, "login_finish", body.clone()).await,
        401
    );
    assert_eq!(
        call_status(&service, WALLET, None, "login_finish", body).await,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn maintenance_refreshes_public_expiry_without_a_member_query() {
    let service = global(50).await;
    let client = client(&service, WALLET, None);
    let before: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    service.clock.set(NOW + 86400);
    service.door.maintain().await.unwrap();
    let after: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    assert_ne!(before.status, after.status);
    let ring = csgn::KeyRing::from_cbor(&after.key_ring).unwrap();
    let verified = ring
        .verify(&after.status, csgn::Kind::SettingsSnapshot, NOW + 86400)
        .unwrap();
    let status: cglb::Status = serde_json::from_slice(verified.payload()).unwrap();
    assert_eq!(status.epoch, 1);
    assert_eq!(status.policy_revision, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn cors_never_authorizes_a_foreign_origin_or_host() {
    let service = global(30).await;
    let http = reqwest::Client::new();
    for (host, origin, allowed) in [
        (WALLET, "https://wallet.example.test", true),
        (WALLET, "https://evil.example.test", false),
        (
            "wallet.example.test.evil.test",
            "https://wallet.example.test.evil.test",
            false,
        ),
    ] {
        let response = http
            .request(
                reqwest::Method::OPTIONS,
                format!("{}/v1/register_begin", service.base),
            )
            .header("host", host)
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_some(),
            allowed
        );
    }
    let response = http
        .post(format!("{}/v1/register_begin", service.base))
        .header("host", WALLET)
        .header("origin", "https://evil.example.test")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_and_foreign_hosts_are_refused_before_body_arrives() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let service = global(30).await;
    for (host, expected) in [(WALLET, "401"), ("api.alpha.example.test", "421")] {
        let mut stream = tokio::net::TcpStream::connect(service.base.trim_start_matches("http://"))
            .await
            .unwrap();
        // Do not transmit any body: the service must authorize before requesting it.
        let headers = format!(
            "POST /v1/passport_issue HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: 12345\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        let mut response = [0u8; 12];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response[..], format!("HTTP/1.1 {expected}").as_bytes());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_responses_errors_and_fallbacks_prohibit_storage() {
    let service = global(100).await;
    let http = reqwest::Client::new();
    for (action, body, expected) in [
        ("register_begin", "{}", 200),
        ("passport_issue", "{}", 401),
        ("login_begin", "{", 400),
        ("unknown", "{}", 404),
    ] {
        let response = http
            .post(format!("{}/v1/{action}", service.base))
            .header("host", WALLET)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
    let response = http
        .post(format!("{}/v1/register_begin", service.base))
        .header("host", WALLET)
        .header("content-type", "application/json")
        .body("x".repeat(256 * 1024 + 1))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        json!({"error":"invalid"})
    );
}
