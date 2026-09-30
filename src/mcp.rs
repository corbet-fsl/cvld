//! Official SDK protocol handling, with the same HTTP authorization boundary.
use crate::{
    api::{ACTIONS, Effect},
    cli::Client,
};
use rmcp::{ErrorData, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde_json::{Value, json};

#[derive(Clone)]
pub struct Mcp {
    pub client: Client,
}
pub fn tools() -> Vec<Tool> {
    ACTIONS
        .iter()
        .map(|action| {
            let mut tool = Tool::new(
                action.name,
                action.description,
                (action.request)()
                    .as_object()
                    .expect("object schema")
                    .clone(),
            );
            tool.output_schema = Some(std::sync::Arc::new(
                (action.response)()
                    .as_object()
                    .expect("object schema")
                    .clone(),
            ));
            tool.annotations =
                Some(ToolAnnotations::new().read_only(action.effect == Effect::Check));
            tool
        })
        .collect()
}
impl ServerHandler for Mcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("cvld", env!("CARGO_PKG_VERSION")))
    }
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: tools(),
            ..Default::default()
        })
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let result = self
            .client
            .call(
                &request.name,
                Value::Object(request.arguments.unwrap_or_default()),
            )
            .await;
        Ok(match result {
            Ok(value) => CallToolResult::structured(value),
            Err(error) => CallToolResult::structured_error(json!({"error": error})),
        }
        .into())
    }
}
