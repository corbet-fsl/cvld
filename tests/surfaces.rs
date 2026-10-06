#[cfg(feature = "development-gate")]
mod support;
use cvld::{api, cli, mcp};
use std::collections::BTreeSet;
#[test]
fn openapi_cli_and_mcp_have_exactly_the_registry_actions() {
    let expected: BTreeSet<_> = api::ACTIONS.iter().map(|a| a.name.to_owned()).collect();
    assert_eq!(expected.len(), api::ACTIONS.len());
    let discovery = api::ACTIONS
        .iter()
        .find(|action| action.name == "login_discoverable_begin")
        .unwrap();
    assert_eq!(discovery.access, api::Access::Public);
    assert_eq!(discovery.scope, api::Scope::Both);
    assert_eq!(discovery.effect, api::Effect::Check);
    for action in api::ACTIONS {
        let projected = cvld::client::forwarding_action(action.name);
        assert_eq!(
            projected.is_some(),
            action.client_access == api::ClientAccess::Forward
        );
        let original = cvld::client::action(action.name).unwrap();
        assert_eq!(
            original.schema()["x-client-access"],
            format!("{:?}", action.client_access).to_lowercase()
        );
    }
    assert_eq!(
        api::action("login_finish").unwrap().client_access,
        api::ClientAccess::Trusted
    );
    assert!(expected.contains("passkey_add"));
    let addition = api::ACTIONS
        .iter()
        .find(|action| action.name == "passkey_add")
        .unwrap();
    assert_eq!(addition.access, api::Access::Member);
    assert_eq!(addition.scope, api::Scope::Community);
    let tool = mcp::tools()
        .into_iter()
        .find(|tool| tool.name == "passkey_add")
        .unwrap();
    assert_eq!(tool.input_schema["type"], "object");
    assert_eq!(tool.output_schema.as_ref().unwrap()["type"], "object");
    let openapi = serde_json::to_value(api::openapi()).unwrap();
    let openapi: BTreeSet<_> = openapi["paths"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| v["post"]["operationId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(expected, openapi);
    let cli: BTreeSet<_> = cli::command()
        .get_subcommands()
        .map(|c| c.get_name().to_owned())
        .filter(|name| !["serve", "openapi", "mcp"].contains(&name.as_str()))
        .collect();
    assert_eq!(expected, cli);
    let mcp: BTreeSet<_> = mcp::tools()
        .into_iter()
        .map(|t| t.name.into_owned())
        .collect();
    assert_eq!(expected, mcp);
}
#[cfg(feature = "development-gate")]
mod http {
    use super::support;
    #[tokio::test(flavor = "multi_thread")]
    async fn every_registered_action_has_a_real_http_route() {
        let running = support::global(100).await;
        for action in cvld::api::ACTIONS {
            let status = support::call_status(
                &running,
                support::WALLET,
                None,
                action.name,
                serde_json::json!({}),
            )
            .await;
            assert_ne!(status, 404, "{} missing", action.name);
            assert_ne!(status, 405, "{} wrong method", action.name);
        }
        assert_eq!(
            support::call_status(
                &running,
                support::WALLET,
                None,
                "not_an_action",
                serde_json::json!({})
            )
            .await,
            404
        );
    }
}
