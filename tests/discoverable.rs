#![cfg(feature = "development-gate")]
mod support;
use cvld::api::*;
use serde_json::{Value, json};
use support::{
    resident::{Resident, strip_prf},
    *,
};

async fn discover(
    service: &Running,
    host: &str,
    device: &mut Resident,
    origin: &str,
) -> (String, Value) {
    let begin = client(service, host, None)
        .call("login_discoverable_begin", json!({}))
        .await
        .unwrap();
    assert!(begin.get("user").is_none());
    assert_eq!(begin["options"]["publicKey"]["allowCredentials"], json!([]));
    assert_eq!(
        begin["options"]["publicKey"]["userVerification"],
        "required"
    );
    let response = device
        .ceremony(begin["options"].clone(), false, origin)
        .await;
    (begin["ceremony"].as_str().unwrap().into(), response)
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_discovers_a_synced_passkey_with_one_ceremony_and_refuses_prf_at_http_ingress() {
    let service = global(100).await;
    let api = client(&service, WALLET, None);
    let begin: Ceremony =
        serde_json::from_value(api.call("register_begin", json!({})).await.unwrap()).unwrap();
    assert_eq!(begin.options["publicKey"]["rp"]["id"], WALLET);
    let mut device = Resident::default();
    let origin = format!("https://{WALLET}");
    let mut response = device.ceremony(begin.options, true, &origin).await;
    assert_eq!(
        call_status(
            &service,
            WALLET,
            None,
            "register_finish",
            json!({"ceremony":begin.ceremony,"credential":response})
        )
        .await,
        400
    );
    let prf = strip_prf(&mut response);
    assert_eq!(prf["enabled"], true);
    let user: User = serde_json::from_value(
        api.call(
            "register_finish",
            json!({"ceremony":begin.ceremony,"credential":response}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let mut phone = device.clone();
    let (ceremony, mut response) = discover(&service, WALLET, &mut phone, &origin).await;
    assert_eq!(
        call_status(
            &service,
            WALLET,
            None,
            "login_finish",
            json!({"ceremony":ceremony,"credential":response})
        )
        .await,
        400
    );
    assert_eq!(strip_prf(&mut response)["results"], prf["results"]);
    let body = json!({"ceremony":ceremony,"credential":response});
    assert_eq!(
        call_status(&service, ROOT, None, "login_finish", body.clone()).await,
        401
    );
    let session: Session =
        serde_json::from_value(api.call("login_finish", body.clone()).await.unwrap()).unwrap();
    assert_eq!(session.user, user.user);
    assert_eq!(
        call_status(&service, WALLET, None, "login_finish", body).await,
        401
    );
    client(&service, WALLET, Some(&session.token))
        .call("logout", json!({}))
        .await
        .unwrap();

    let (ceremony, mut response) = discover(&service, WALLET, &mut phone, &origin).await;
    strip_prf(&mut response);
    service.clock.set(NOW + 301);
    assert_eq!(
        call_status(
            &service,
            WALLET,
            None,
            "login_finish",
            json!({"ceremony":ceremony,"credential":response})
        )
        .await,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn community_restore_from_the_vault_origin_preserves_membership_and_revocation() {
    let global = global(100).await;
    let (_wallet, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let host = "api.alpha.example.test";
    let origin = "https://vault.alpha.example.test";
    for (candidate, allowed) in [
        (origin, true),
        ("https://vault.beta.example.test", false),
        ("https://vault.alpha.example.test.evil.test", false),
        ("https://wallet.example.test", false),
    ] {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/login_discoverable_begin", service.base))
            .header("host", host)
            .header("origin", candidate)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().is_success(), allowed);
        assert_eq!(
            response
                .headers()
                .contains_key("access-control-allow-origin"),
            allowed
        );
    }
    let api = client(&service, host, None);
    let proof = presentation(&service, host, None, &passport).await;
    let begin: Ceremony = serde_json::from_value(
        api.call("register_begin", json!({"passport":proof}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(begin.options["publicKey"]["rp"]["id"], "alpha.example.test");
    assert_eq!(
        begin.options["publicKey"]["authenticatorSelection"]["residentKey"],
        "required"
    );
    let mut device = Resident::default();
    let mut response = device.ceremony(begin.options, true, origin).await;
    strip_prf(&mut response);
    let credential: ckyh::RegisterPublicKeyCredential =
        serde_json::from_value(response.clone()).unwrap();
    let credential_id = credential.raw_id.as_ref().to_vec();
    let user: User = serde_json::from_value(
        api.call(
            "register_finish",
            json!({"ceremony":begin.ceremony,"credential":response}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let (ceremony, mut response) = discover(&service, host, &mut device, origin).await;
    let prf = strip_prf(&mut response);
    let session: Session = serde_json::from_value(
        api.call(
            "login_finish",
            json!({"ceremony":ceremony,"credential":response}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let before = client(&service, host, Some(&session.token))
        .call("lobby", json!({}))
        .await
        .unwrap();

    let mut phone = device.clone();
    let (ceremony, mut response) = discover(&service, host, &mut phone, origin).await;
    assert_eq!(strip_prf(&mut response), prf);
    let restored: Session = serde_json::from_value(
        api.call(
            "login_finish",
            json!({"ceremony":ceremony,"credential":response}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(restored.user, user.user);
    let restored_client = client(&service, host, Some(&restored.token));
    assert_eq!(
        restored_client.call("lobby", json!({})).await.unwrap(),
        before
    );
    let (ceremony, mut response) = discover(&service, host, &mut phone, origin).await;
    strip_prf(&mut response);
    restored_client
        .call("passkey_revoke", json!({"credential":credential_id}))
        .await
        .unwrap();
    assert_eq!(
        call_status(
            &service,
            host,
            None,
            "login_finish",
            json!({"ceremony":ceremony,"credential":response})
        )
        .await,
        401
    );
    assert_eq!(
        call_status(&service, host, Some(&session.token), "lobby", json!({})).await,
        401
    );
    assert_eq!(
        call_status(&service, host, Some(&restored.token), "lobby", json!({})).await,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn operator_discovery_keeps_the_configured_identity_and_root_host() {
    let service = global(100).await;
    let api = client(&service, ROOT, None);
    let begin: Ceremony = serde_json::from_value(
        api.call(
            "register_begin",
            json!({"bootstrap":"synthetic-operator-enrolment-capability"}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let origin = format!("https://{ROOT}");
    let mut device = Resident::default();
    let mut response = device.ceremony(begin.options, true, &origin).await;
    strip_prf(&mut response);
    api.call(
        "register_finish",
        json!({"ceremony":begin.ceremony,"credential":response}),
    )
    .await
    .unwrap();
    let (ceremony, mut response) = discover(&service, ROOT, &mut device, &origin).await;
    strip_prf(&mut response);
    let session: Session = serde_json::from_value(
        api.call(
            "login_finish",
            json!({"ceremony":ceremony,"credential":response}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(session.user, "00000000-0000-4000-8000-000000000001");
    assert_eq!(session.role, Role::Root);
    assert_eq!(
        call_status(&service, WALLET, Some(&session.token), "logout", json!({})).await,
        401
    );
    client(&service, ROOT, Some(&session.token))
        .call("logout", json!({}))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn root_garden_uses_its_scope_rp_and_exact_portal_origin() {
    let service = global(100).await;
    let origin = "https://admin.root.example.test";
    let http = reqwest::Client::new();
    for (host, candidate, allowed) in [
        (ROOT, origin, true),
        (ROOT, "https://admin.alpha.example.test", false),
        (ROOT, "https://admin.root.example.test.evil.test", false),
        ("api.root.example.test", origin, false),
    ] {
        let response = http
            .post(format!("{}/v1/login_discoverable_begin", service.base))
            .header("host", host)
            .header("origin", candidate)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().is_success(), allowed);
        assert_eq!(
            response
                .headers()
                .contains_key("access-control-allow-origin"),
            allowed
        );
    }
    let api = client(&service, ROOT, None);
    let begin: Ceremony = serde_json::from_value(
        api.call(
            "register_begin",
            json!({
                "bootstrap":"synthetic-operator-enrolment-capability"
            }),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(begin.options["publicKey"]["rp"]["id"], "root.example.test");
    let mut device = Resident::default();
    let mut response = device.ceremony(begin.options, true, origin).await;
    strip_prf(&mut response);
    let user: User = serde_json::from_value(
        api.call(
            "register_finish",
            json!({
                "ceremony":begin.ceremony,"credential":response
            }),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let (ceremony, mut response) = discover(&service, ROOT, &mut device, origin).await;
    strip_prf(&mut response);
    let mut foyer = cvld::client::Client::new(api);
    let session = foyer
        .authenticate(json!({"ceremony":ceremony,"credential":response}))
        .await
        .unwrap();
    assert_eq!(session.user, user.user);
    assert_eq!(session.role, "root");
    foyer.forward("logout", json!({})).await.unwrap();
}
