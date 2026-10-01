//! Portable client projection of this owner's generated OpenAPI contract.
//! No server authority or mutable session state is exposed by the registry.

use crate::error::{Error, Result};
use serde_json::Value;
use std::{collections::BTreeMap, future::Future, sync::LazyLock};

#[cfg(all(feature = "client-http", not(target_arch = "wasm32")))]
#[path = "client_http.rs"]
mod http;
#[cfg(all(feature = "client-http", not(target_arch = "wasm32")))]
pub use http::HttpClient;

#[cfg(all(feature = "client-browser", target_arch = "wasm32"))]
#[path = "client_browser.rs"]
mod browser;
#[cfg(all(feature = "client-browser", target_arch = "wasm32"))]
pub use browser::BrowserClient;

#[cfg(any(feature = "client-http", feature = "client-browser"))]
fn origin(base: &str, host: &str) -> Result<url::Url> {
    let url = url::Url::parse(base).map_err(|_| Error::Invalid)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::Invalid);
    }
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(Error::Invalid);
    }
    if url.scheme() == "https" && url.host_str() != Some(host) {
        return Err(Error::WrongHost);
    }
    Ok(url)
}

#[cfg(any(feature = "client-http", feature = "client-browser"))]
fn decode_response(name: &str, status: u16, body: &[u8]) -> Result<Value> {
    if status != 200 {
        let error: crate::error::ErrorBody =
            serde_json::from_slice(body).map_err(|_| Error::Reconcile)?;
        return Err(if error.error.http_status() == status {
            error.error
        } else {
            Error::Reconcile
        });
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| Error::Reconcile)?;
    validate_response(name, &value)?;
    Ok(value)
}

static DOCUMENT: LazyLock<Value> = LazyLock::new(|| {
    #[cfg(feature = "server")]
    {
        serde_json::to_value(crate::api::openapi()).expect("the owner contract is serializable")
    }
    #[cfg(not(feature = "server"))]
    {
        serde_json::from_str(include_str!("../docs/openapi.json"))
            .expect("the checked generated door contract is JSON")
    }
});

static RESPONSES: LazyLock<Result<BTreeMap<String, jsonschema::Validator>>> = LazyLock::new(|| {
    let paths = DOCUMENT["paths"].as_object().ok_or(Error::Reconcile)?;
    paths
        .values()
        .map(|item| {
            let operation = &item["post"];
            let name = operation["operationId"].as_str().ok_or(Error::Reconcile)?;
            let mut schema =
                operation["responses"]["200"]["content"]["application/json"]["schema"].clone();
            schema
                .as_object_mut()
                .ok_or(Error::Reconcile)?
                .insert("components".into(), DOCUMENT["components"].clone());
            // Network and file resolvers are disabled in Cargo features.
            let validator = jsonschema::validator_for(&schema).map_err(|_| Error::Reconcile)?;
            Ok((name.to_owned(), validator))
        })
        .collect()
});

/// Validate a successful response against the exact owner's generated DTO schema.
/// Malformed replies after dispatch are uncertain, even if JSON parsing succeeds.
pub fn validate_response(name: &str, response: &Value) -> Result<()> {
    let validators = RESPONSES.as_ref().map_err(|_| Error::Reconcile)?;
    let validator = validators.get(name).ok_or(Error::Invalid)?;
    if !validator.is_valid(response) {
        return Err(Error::Reconcile);
    }
    Ok(())
}

/// Original owner schema, including exact roles, scopes, effects and JSON types.
pub fn contract() -> &'static Value {
    &DOCUMENT
}

/// A borrowed operation from the generated contract, never a caller-built grant.
#[derive(Clone, Copy)]
pub struct Action {
    path: &'static str,
    operation: &'static Value,
}

impl Action {
    /// Owner's original HTTP path.
    pub fn path(&self) -> &'static str {
        self.path
    }

    /// Original operation schema and role/effect/scope metadata.
    pub fn schema(&self) -> &'static Value {
        self.operation
    }
}

/// Look up a public owner operation without guessing a route from input text.
pub fn action(name: &str) -> Option<Action> {
    DOCUMENT
        .get("paths")?
        .as_object()?
        .iter()
        .find_map(|(path, item)| {
            let operation = item.get("post")?;
            (operation.get("operationId")?.as_str()? == name).then_some(Action { path, operation })
        })
}

/// An authenticated HTTP runtime selected by the trusted device composition.
/// Request JSON contains public assertions and opaque signed bytes, never PRF
/// results or roots. The server independently checks all roles and authority.
pub trait Transport {
    /// Send exactly the owner's path to the selected pinned door origin.
    fn send(&mut self, path: &str, request: Value) -> impl Future<Output = Result<Value>>;
}

/// Portable generated-contract client; runtime credentials stay in its transport.
pub struct Client<T> {
    transport: T,
}

impl<T: Transport> Client<T> {
    /// Compose a runtime without manufacturing authentication or permissions.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Forward one registered operation, preserving the owner's response/error.
    pub async fn call(&mut self, name: &str, request: Value) -> Result<Value> {
        let action = action(name).ok_or(Error::Invalid)?;
        let response = self.transport.send(action.path(), request).await?;
        validate_response(name, &response)?;
        Ok(response)
    }
}
