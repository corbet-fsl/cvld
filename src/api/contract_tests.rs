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

#[cfg(all(test, feature = "server"))]
mod committed_contract_tests {
    use serde_json::Value;

    /// The client validates every forwarded answer against the COMMITTED document, so a
    /// file older than the server's DTOs refuses a genuine answer as malformed: the
    /// consumer can only report that flat `Reconcile`, which reads as a transient refusal
    /// and hides the acceptance the server already wrote. CI regenerates the file and
    /// diffs it; this test is the same freshness check where a lane can read it, and it
    /// names the two account answers a newcomer's join acceptance travels on.
    #[test]
    fn the_committed_contract_matches_the_generated_one() {
        #[allow(unused_mut)]
        let mut generated = serde_json::to_value(crate::api::openapi()).unwrap();
        // The checked document is the release contract: CI emits it with the
        // default features, and `development-gate` is the only feature that adds
        // registry actions. Remove exactly those actions (asserting each was
        // the one named) so the comparison stays byte-exact for the
        // feature-independent document instead of pinning development-only
        // paths into the release schema, or skipping the check whenever the
        // feature is on.
        #[cfg(feature = "development-gate")]
        {
            let paths = generated["paths"]
                .as_object_mut()
                .expect("the generated contract declares paths");
            for action in ["development_gate", "development_voucher_link"] {
                let operation = paths.remove(&format!("/v1/{action}")).unwrap_or_else(|| {
                    panic!("the development feature declares the {action} action")
                });
                assert_eq!(operation["post"]["operationId"], action);
            }
        }
        let committed: Value =
            serde_json::from_str(include_str!("../../docs/openapi.json")).unwrap();
        let account_variant = |document: &Value, action: &str| {
            document["components"]["schemas"]["AccountServiceResponse"]["oneOf"]
                .as_array()
                .expect("the account response is a union of actions")
                .iter()
                .find(|variant| variant["properties"]["action"]["enum"][0] == action)
                .unwrap_or_else(|| panic!("the account response declares {action}"))
                .clone()
        };
        for document in [&committed, &generated] {
            let extended = account_variant(document, "applyExtended");
            assert!(
                extended["properties"]["value"]["properties"]
                    .get("join_publication")
                    .is_some(),
                "an accepted extended answer carries the community publication"
            );
            let status = account_variant(document, "status");
            assert!(
                status["properties"]["value"]["properties"]["extended"]["properties"]
                    .get("joinPublication")
                    .is_some(),
                "a status answer carries it in the extended evidence"
            );
        }
        assert_eq!(
            committed, generated,
            "docs/openapi.json is stale: regenerate it with `cargo run --locked -- openapi`"
        );
    }
}
