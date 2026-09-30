#[cfg(feature = "development-gate")]
mod support;
use cvld::{api, cli, mcp};
use std::collections::BTreeSet;
#[test]
fn openapi_cli_and_mcp_have_exactly_the_registry_actions() {
    let expected: BTreeSet<_> = api::ACTIONS.iter().map(|a| a.name.to_owned()).collect();
    assert_eq!(expected.len(), api::ACTIONS.len());
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
