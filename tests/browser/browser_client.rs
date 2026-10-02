#![cfg(target_arch = "wasm32")]
#[cfg(owned_browser_coverage)]
use browser_coverage_runtime as _;
use cvld::{
    client::{BrowserClient, Client, Transport, action, contract, validate_response},
    error::Error,
};
use serde_json::json;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

const BASE: &str = "https://wallet.example.test";
const HOST: &str = "wallet.example.test";

#[wasm_bindgen_test]
async fn generated_browser_client_reaches_the_real_keyhole_and_door() {
    let fixture: serde_json::Value = gloo_net::http::Request::get("/__fixture")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session = fixture["session"].as_str().unwrap().to_owned();
    let mut public = Client::new(BrowserClient::new(BASE.into(), HOST.into(), None).unwrap());
    assert!(matches!(
        public
            .forward("login_finish", fixture["authentication"].clone())
            .await,
        Err(Error::Invalid)
    ));
    let info = public
        .authenticate(fixture["authentication"].clone())
        .await
        .unwrap();
    assert_eq!(info.user, fixture["user"].as_str().unwrap());
    assert_eq!(info.role, "member");
    assert!(serde_json::to_value(&info).unwrap().get("token").is_none());
    public.forward("logout", json!({})).await.unwrap();
    let metadata = action("global_public").unwrap();
    assert_eq!(metadata.path(), "/v1/global_public");
    assert_eq!(metadata.schema()["x-role"], "public");
    assert_eq!(contract()["info"]["title"], "cvld");
    assert!(public.call("global_public", json!({})).await.unwrap()["issuer"].is_array());
    assert!(matches!(
        validate_response("unknown", &json!({})),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        public.call("passport_challenge", json!({})).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        public.call("../logout", json!({})).await,
        Err(Error::Invalid)
    ));
    let mut owner = BrowserClient::new(BASE.into(), HOST.into(), Some(session)).unwrap();
    let mut member = Client::new(owner.clone());
    assert!(member.call("passport_challenge", json!({})).await.is_ok());
    assert!(matches!(
        member
            .call(
                "global_suspend",
                json!({"user":"wrong","until":1_800_000_001})
            )
            .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        owner.send("/unregistered", json!({})).await,
        Err(Error::Invalid)
    ));
    assert!(matches!(
        owner.call("unknown", json!({})).await,
        Err(Error::Invalid)
    ));
    assert!(owner.send("/v1/logout", json!({})).await.is_ok());
    assert!(matches!(
        member.call("passport_challenge", json!({})).await,
        Err(Error::Unauthorized)
    ));
    let malformed =
        BrowserClient::new(BASE.into(), HOST.into(), Some("bad\nheader".into())).unwrap();
    assert!(matches!(
        malformed.call("global_public", json!({})).await,
        Err(Error::Invalid)
    ));
    for session in fixture["fault_sessions"].as_array().unwrap() {
        let owner = BrowserClient::new(
            BASE.into(),
            HOST.into(),
            Some(session.as_str().unwrap().into()),
        )
        .unwrap();
        assert!(matches!(
            owner.call("logout", json!({})).await,
            Err(Error::Reconcile)
        ));
        // The original mutation committed, despite a malformed, redirected,
        // oversized or interrupted reply. No replacement operation is sent.
        assert!(matches!(
            owner.call("passport_challenge", json!({})).await,
            Err(Error::Unauthorized)
        ));
    }
    let counts: Vec<usize> = gloo_net::http::Request::get("/__faults")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(counts, vec![1; 11]);
}

#[wasm_bindgen_test]
fn browser_origin_is_exact_and_cannot_use_the_native_fixture_host_override() {
    for base in [
        "invalid",
        "ftp://localhost",
        "http://remote.example.test",
        "https://user@wallet.example.test",
        "https://:password@wallet.example.test",
        "https://wallet.example.test/path",
        "https://wallet.example.test/?q=x",
        "https://wallet.example.test/#fragment",
    ] {
        assert!(matches!(
            BrowserClient::new(base.into(), HOST.into(), None),
            Err(Error::Invalid)
        ));
    }
    assert!(matches!(
        BrowserClient::new(BASE.into(), "foreign.example.test".into(), None),
        Err(Error::WrongHost)
    ));
    assert!(matches!(
        BrowserClient::new("http://localhost".into(), HOST.into(), None),
        Err(Error::WrongHost)
    ));
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        assert!(BrowserClient::new(format!("http://{host}"), host.into(), None).is_ok());
    }
}
