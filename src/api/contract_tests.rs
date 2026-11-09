//! The client in `cvld-client` reads the committed generated contract of its feature set
//! (`docs/openapi.json`, or `docs/openapi.development.json` under `development-gate`), never
//! the live registry. These tests make the committed copy equal the live `openapi()` byte
//! for byte, so an API change without regenerated documents can never pass.

/// The committed copy this build's client reads, and the command that regenerates it.
#[cfg(not(feature = "development-gate"))]
const COMMITTED: (&str, &str) = (
    include_str!("../../docs/openapi.json"),
    "cargo run --locked -- openapi > docs/openapi.json",
);
#[cfg(feature = "development-gate")]
const COMMITTED: (&str, &str) = (
    include_str!("../../docs/openapi.development.json"),
    "cargo run --locked --features development-gate -- openapi > docs/openapi.development.json",
);

#[test]
fn contract_equals_live_registry() {
    let (committed, regenerate) = COMMITTED;
    // `cvld openapi` prints `openapi_json()` with a final newline.
    let live = format!("{}\n", super::openapi_json());
    assert!(
        committed == live,
        "the committed contract differs from the live registry of this feature set; \
         regenerate it in the cvld checkout: `{regenerate}`"
    );
    // The client serves exactly that document.
    let document: serde_json::Value = serde_json::from_str(&live).unwrap();
    assert_eq!(cvld_client::client::contract(), &document, "{regenerate}");
}

/// Both development actions are in the development contract, neither in the default one.
#[test]
fn development_actions_follow_the_feature_set() {
    let paths = cvld_client::client::contract()["paths"]
        .as_object()
        .unwrap();
    for action in ["/v1/development_gate", "/v1/development_voucher_link"] {
        assert_eq!(
            paths.contains_key(action),
            cfg!(feature = "development-gate"),
            "{action}"
        );
    }
}

/// The CLI's (and every runtime's) known-action check accepts exactly the live registry:
/// `client::action` is what `HttpClient::call` and `OhttpClient::call` consult before
/// sending anything.
#[test]
fn client_actions_are_exactly_the_live_registry() {
    use std::collections::BTreeSet;
    let registry: BTreeSet<&str> = super::ACTIONS.iter().map(|a| a.name).collect();
    let paths = cvld_client::client::contract()["paths"]
        .as_object()
        .unwrap();
    let accepted: BTreeSet<&str> = paths
        .values()
        .filter_map(|item| item.get("post")?.get("operationId")?.as_str())
        .filter(|name| cvld_client::client::action(name).is_some())
        .collect();
    assert_eq!(accepted, registry);
    for name in &registry {
        assert!(cvld_client::client::action(name).is_some(), "{name}");
    }
    for unknown in [
        "",
        "account_record_object",
        "not_an_action",
        "../logout",
        "logout/",
    ] {
        assert!(cvld_client::client::action(unknown).is_none(), "{unknown}");
    }
}

/// The release CLI (`cli::Client`) refuses a name outside the registry before any dispatch:
/// the base points at a closed loopback port, so only the local check can answer.
#[tokio::test]
async fn cli_client_refuses_unregistered_actions_before_dispatch() {
    let client = crate::cli::Client::new("http://127.0.0.1:9/".into(), "x".into(), None).unwrap();
    for unknown in ["not_an_action", "account_record_object", "../logout"] {
        assert!(matches!(
            client.call(unknown, serde_json::json!({})).await,
            Err(crate::error::Error::Invalid)
        ));
    }
}
