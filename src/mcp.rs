//! Official SDK protocol handling, with the same HTTP authorization boundary.
use crate::{
    api::{ACTIONS, Effect},
    cli::Client,
};
use rmcp::{ErrorData, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde_json::{Value, json};

mod bounded;

/// Original SDK stdio with an intake byte bound on every physical JSON-RPC
/// frame. The maintained SDK retains parsing, cancellation and protocol errors.
pub fn stdio() -> (
    impl tokio::io::AsyncRead + Send + Unpin + 'static,
    impl tokio::io::AsyncWrite + Send + Unpin + 'static,
) {
    (
        bounded::BoundedRead::new(tokio::io::stdin(), bounded::FRAME_BYTES),
        tokio::io::stdout(),
    )
}

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
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let result = match bounded::arguments_fit(&request.name, &arguments) {
            Ok(()) => self.client.call(&request.name, arguments).await,
            Err(error) => Err(error),
        };
        Ok(match result {
            Ok(value) => CallToolResult::structured(value),
            Err(error) => CallToolResult::structured_error(json!({"error": error})),
        }
        .into())
    }
}
