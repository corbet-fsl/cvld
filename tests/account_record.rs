//! Binary contract and real unconfigured HTTP refusals; no G2 qualification.
#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
mod payment_support;
mod support;
use cmty::cplc;
use cvld::{
    api::*,
    client::{Client, HttpClient},
    error::Error,
    service::Door,
};
use serde_json::json;
use std::sync::Arc;
use support::*;
#[path = "production_journey/contacts.rs"]
mod contacts;
#[allow(dead_code)]
#[path = "production_journey/payment.rs"]
mod payment;
const HOST: &str = "api.alpha.example.test";

#[test]
fn binary_resource_preserves_json_action_schema_gating() {
    let document = serde_json::to_value(cvld::api::openapi()).unwrap();
    let resource = &document["paths"]["/v1/account_record_object"];
    assert!(resource.get("post").is_none());
    assert_eq!(resource["get"]["x-cvld-resource"], "account-record-object");
    assert_eq!(
        resource["get"]["responses"]["200"]["content"]["application/octet-stream"]["schema"],
        json!({"type":"string","format":"binary"})
    );
    assert!(cvld::client::action("account_record_object").is_none());
    assert!(
        cvld::client::forwarding_contract()["paths"]
            .get("/v1/account_record_object")
            .is_none()
    );
    assert!(cvld::client::forwarding_action("account_record").is_some());
    cvld::client::validate_response(
        "account_record",
        &json!({"path":"/v1/account_record_object","media_type":"application/octet-stream"}),
    )
    .unwrap();
    assert!(matches!(
        cvld::client::validate_response(
            "account_record",
            &json!({"path":"/v1/account_record_object"})
        ),
        Err(Error::Reconcile)
    ));
    // A missing binary descriptor must not disable unrelated JSON validators.
    cvld::client::validate_response("logout", &json!({})).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_member_has_no_common_object_until_actual_native_publication() {
    let (global, contact_wire, cohort) = contacts::production(true).await;
    let (_, passport, public) = contacts::wallet(&global, cohort).await;
    assert_eq!(contact_wire.calls(), 4);
    let service = payment::community(
        &public,
        payment_support::Wire::new(payment_support::Reply::Success),
    )
    .await;
    let member = enrol_community(&service, HOST, &passport).await;
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "account_record",
            json!({})
        )
        .await,
        503
    );
    let before: Lobby = serde_json::from_value(
        client(&service, HOST, Some(&member.session))
            .call("lobby", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let request = reqwest::Client::new();
    for (host, suffix, expected) in [
        (HOST, "", 503),
        (HOST, "?recipient=arbitrary", 400),
        ("api.root.example.test", "", 421),
        ("api.admin.alpha.example.test", "", 421),
    ] {
        let response = request
            .get(format!("{}/v1/account_record_object{suffix}", service.base))
            .header("host", host)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body: cvld::error::ErrorBody = response.json().await.unwrap();
        assert_eq!(body.error.http_status(), expected);
    }
    let after: Lobby = serde_json::from_value(
        client(&service, HOST, Some(&member.session))
            .call("lobby", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(before.member_id, after.member_id);
    assert_eq!(before.state, after.state);
    let feed: TrustFeed = serde_json::from_value(
        client(&service, HOST, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(feed.balance.is_none());
}

#[tokio::test]
async fn exact_budget_is_owner_bounded_before_dispatch_and_http_never_qualifies() {
    let mut client =
        Client::new(HttpClient::new("http://127.0.0.1:1".into(), HOST.into(), None).unwrap());
    assert!(matches!(
        client.account_record_object(0).await,
        Err(Error::Invalid)
    ));
    assert!(matches!(
        client
            .account_record_object(czkp::record::MAX_DOWNLOAD_BYTES as usize + 1)
            .await,
        Err(Error::Invalid)
    ));
    assert!(matches!(
        client
            .account_record_object(czkp::record::MAX_DOWNLOAD_BYTES as usize)
            .await,
        Err(Error::WrongHost)
    ));
}
