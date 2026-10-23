//! Portable client projection of this owner's generated OpenAPI contract.
//! No server authority or mutable session state is exposed by the registry.

use crate::error::{Error, Result};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, future::Future, sync::LazyLock};

#[path = "client_record.rs"]
pub(crate) mod record;

#[cfg(any(
    feature = "client-http",
    feature = "client-browser",
    feature = "client-ohttp"
))]
#[path = "client_json.rs"]
mod json;

#[cfg(all(feature = "client-http", not(target_arch = "wasm32")))]
#[path = "client_http.rs"]
mod http;
#[cfg(all(feature = "client-http", not(target_arch = "wasm32")))]
pub use http::HttpClient;

#[cfg(feature = "client-ohttp")]
#[path = "client_ohttp.rs"]
mod ohttp;
#[cfg(feature = "client-ohttp")]
pub use ohttp::OhttpClient;

#[cfg(all(feature = "client-browser", target_arch = "wasm32"))]
#[path = "client_browser.rs"]
mod browser;
#[cfg(all(feature = "client-browser", target_arch = "wasm32"))]
pub use browser::BrowserClient;

#[cfg(any(
    feature = "client-http",
    feature = "client-browser",
    feature = "client-ohttp"
))]
fn origin(base: &str, host: &str) -> Result<url::Url> {
    let url = url::Url::parse(base).map_err(Error::Invalid.redact())?;
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

#[cfg(any(
    feature = "client-http",
    feature = "client-browser",
    feature = "client-ohttp"
))]
fn decode_response(name: &str, status: u16, body: &[u8]) -> Result<Value> {
    if status != 200 {
        let error: crate::error::ErrorBody = json::decode(body)?;
        return Err(match error.error() {
            Some(error) if error.http_status() == status => error,
            _ => Error::Reconcile,
        });
    }
    let value: Value = json::decode(body)?;
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
        #[allow(unused_mut)]
        let mut document: Value = serde_json::from_str(include_str!("../docs/openapi.json"))
            .expect("the checked generated door contract is JSON");
        #[cfg(feature = "development-gate-client")]
        add_development_gate(&mut document);
        document
    }
});

/// The checked contract never contains the development action. Client-only
/// development builds derive it from `logout`, which has the identical empty
/// request and response, and replace exactly the server's declared metadata.
#[cfg(all(feature = "development-gate-client", not(feature = "server")))]
fn add_development_gate(document: &mut Value) {
    let paths = document
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .expect("the checked generated door contract has an object of paths");
    let mut path = paths
        .get("/v1/logout")
        .cloned()
        .expect("the checked generated door contract declares logout");
    let operation = path
        .get_mut("post")
        .and_then(Value::as_object_mut)
        .expect("logout is a POST operation");
    for (key, value) in [
        ("operationId", "development_gate"),
        (
            "summary",
            "Pass the development-only synthetic uniqueness gate",
        ),
        ("x-role", "member"),
        ("x-scope", "global"),
        ("x-effect", "record"),
        ("x-client-access", "forward"),
    ] {
        operation.insert(key.into(), value.into());
    }
    paths.insert("/v1/development_gate".into(), path);
}

#[cfg(all(test, feature = "development-gate-client", not(feature = "server")))]
mod development_gate_client_tests {
    #[test]
    fn exposes_the_development_action_without_the_server() {
        let operation = super::action("development_gate").expect("declared");
        assert_eq!(operation.path(), "/v1/development_gate");
        assert!(super::action("logout").is_some());
    }
}

// A malformed generated contract is a build defect, not an unknown caller action.
static PATHS: LazyLock<&'static Map<String, Value>> = LazyLock::new(|| {
    DOCUMENT["paths"]
        .as_object()
        .expect("the checked generated door contract has an object of paths")
});

static FORWARD_DOCUMENT: LazyLock<Value> = LazyLock::new(|| {
    let mut document = DOCUMENT.clone();
    // Use the same checked paths as action lookup: malformed owner metadata
    // remains a build defect, while missing visibility fails closed.
    let paths = document["paths"]
        .as_object_mut()
        .expect("the checked generated door contract has an object of paths");
    paths.retain(|_, item| item["post"]["x-client-access"] == "forward");
    document
});

static RESPONSES: LazyLock<Result<BTreeMap<String, jsonschema::Validator>>> = LazyLock::new(|| {
    PATHS
        .iter()
        .filter(|(path, item)| {
            // Only this owner's explicitly declared fixed binary resource is
            // excluded. Missing/malformed JSON actions still fail below.
            !(path.as_str() == record::PATH
                && item.get("post").is_none()
                && item["get"]["x-cvld-resource"] == record::RESOURCE
                && item["get"]["operationId"] == "account_record_object"
                && item["get"]["responses"]["200"]["content"]["application/octet-stream"]["schema"]
                    == serde_json::json!({"type":"string","format":"binary"}))
        })
        .map(|(_, item)| {
            let operation = &item["post"];
            let name = operation["operationId"].as_str().ok_or(Error::Reconcile)?;
            let mut schema =
                operation["responses"]["200"]["content"]["application/json"]["schema"].clone();
            schema
                .as_object_mut()
                .ok_or(Error::Reconcile)?
                .insert("components".into(), DOCUMENT["components"].clone());
            // Network and file resolvers are disabled in Cargo features.
            let validator =
                jsonschema::validator_for(&schema).map_err(Error::Reconcile.redact())?;
            Ok((name.to_owned(), validator))
        })
        .collect()
});

/// Validate a successful response against the exact owner's generated DTO schema.
/// Malformed replies after dispatch are uncertain, even if JSON parsing succeeds.
pub fn validate_response(name: &str, response: &Value) -> Result<()> {
    let validators = RESPONSES.as_ref().map_err(Error::Reconcile.redact())?;
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

/// Owner-derived device surface. Missing visibility metadata fails closed.
/// Trusted authentication results are consumed privately instead of forwarded.
pub fn forwarding_contract() -> &'static Value {
    &FORWARD_DOCUMENT
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
    PATHS.iter().find_map(|(path, item)| {
        let operation = item.get("post")?;
        (operation.get("operationId")?.as_str()? == name).then_some(Action { path, operation })
    })
}

/// Look up only operations whose raw responses may leave the trusted runtime.
pub fn forwarding_action(name: &str) -> Option<Action> {
    action(name).filter(|action| action.schema()["x-client-access"] == "forward")
}

/// An authenticated HTTP runtime selected by the trusted device composition.
/// Request JSON contains public assertions and opaque signed bytes, never PRF
/// results or roots. The server independently checks all roles and authority.
pub trait Transport {
    /// Send exactly the owner's path to the selected pinned door origin.
    fn send(&mut self, path: &str, request: Value) -> impl Future<Output = Result<Value>>;
}

/// Trusted transport capability for installing a freshly verified bearer.
/// Implementations retain it privately and never return it through device JSON.
pub trait SessionTransport: Transport {
    /// Replace this origin's session, wiping the previous bearer on drop.
    fn adopt_session(&mut self, token: zeroize::Zeroizing<String>);
}

mod sealed {
    pub trait Authenticated {}
}

/// Only cvld's original HTTP runtimes authenticate the configured HTTPS origin.
/// An arbitrary caller transport can forward operations and retain sessions, but
/// cannot claim this owner capability for a live server observation.
/// ```compile_fail
/// use cvld::client::{AuthenticatedTransport, SessionTransport, Transport};
/// struct CallerTransport;
/// impl Transport for CallerTransport {
///     async fn send(&mut self, _: &str, _: serde_json::Value) -> cvld::error::Result<serde_json::Value> {
///         unreachable!()
///     }
/// }
/// impl SessionTransport for CallerTransport {
///     fn adopt_session(&mut self, _: zeroize::Zeroizing<String>) {}
/// }
/// impl AuthenticatedTransport for CallerTransport {
///     fn authenticated_origin(&self) -> cvld::error::Result<String> {
///         unreachable!()
///     }
///     async fn account_record_object(&mut self, _: usize) -> cvld::error::Result<Vec<u8>> {
///         unreachable!()
///     }
/// }
/// ```
pub trait AuthenticatedTransport: SessionTransport + sealed::Authenticated {
    /// Canonical scheme/host/port of the actual configured HTTPS endpoint.
    /// HTTP loopback fixture overrides cannot qualify. This inert configuration
    /// accessor does not replace a fresh successful authenticated server call.
    fn authenticated_origin(&self) -> Result<String>;
    /// Fetch the fixed anonymous whole-object resource at this exact HTTPS
    /// origin. Length is a bounded resource budget, never proof authority.
    /// The relying owner must obtain it from a current authenticated descriptor
    /// and verify the returned object with that original descriptor afterward.
    fn account_record_object(
        &mut self,
        expected_length: usize,
    ) -> impl Future<Output = Result<Vec<u8>>>;
}

/// Public result of authentication; the server bearer stays in its transport.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInfo {
    /// Community-local authenticated user.
    pub user: String,
    /// Role verified by the owner's response contract.
    pub role: String,
    /// Exclusive server session deadline.
    pub expires: u64,
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
    /// Forward only owner-marked shell-safe responses, before any dispatch.
    pub async fn forward(&mut self, name: &str, request: Value) -> Result<Value> {
        forwarding_action(name).ok_or(Error::Invalid)?;
        self.call(name, request).await
    }
}

impl<T: SessionTransport> Client<T> {
    /// Finish a real passkey login and adopt its session at the same pinned origin.
    /// The request contains the public assertion from Passkeys, never its PRF.
    pub async fn authenticate(&mut self, request: Value) -> Result<SessionInfo> {
        self.adopt("login_finish", request).await
    }
    /// Open or renew a community session from a device key's signed nonce, with no passkey.
    pub async fn authenticate_device(&mut self, request: Value) -> Result<SessionInfo> {
        self.adopt("device_session_finish", request).await
    }
    /// Fork this live wallet session (C6 `session_fork`) and adopt the sibling's bearer in
    /// `sibling`, a client of the same origin; this client keeps its own session. The bearer
    /// never reaches the caller.
    pub async fn fork_into<U: SessionTransport>(
        &mut self,
        sibling: &mut Client<U>,
    ) -> Result<SessionInfo> {
        let (token, info) = self
            .trusted("session_fork", Value::Object(Default::default()))
            .await?;
        sibling.transport.adopt_session(token);
        Ok(info)
    }
    /// Open an admin session from a device key's signed nonce and one confirmation stamp.
    pub async fn authenticate_garden(&mut self, request: Value) -> Result<SessionInfo> {
        self.adopt("garden_session_finish", request).await
    }
    async fn adopt(&mut self, name: &str, request: Value) -> Result<SessionInfo> {
        let (token, info) = self.trusted(name, request).await?;
        self.transport.adopt_session(token);
        Ok(info)
    }
    async fn trusted(
        &mut self,
        name: &str,
        request: Value,
    ) -> Result<(zeroize::Zeroizing<String>, SessionInfo)> {
        let action = action(name).ok_or(Error::Invalid)?;
        if action.schema()["x-client-access"] != "trusted" {
            return Err(Error::Invalid);
        }
        let response = self.call(name, request).await?;
        let Value::Object(mut fields) = response else {
            return Err(Error::Reconcile);
        };
        let Some(Value::String(token)) = fields.remove("token") else {
            return Err(Error::Reconcile);
        };
        let token = zeroize::Zeroizing::new(token);
        let info =
            serde_json::from_value(Value::Object(fields)).map_err(Error::Reconcile.redact())?;
        Ok((token, info))
    }
}

impl<T: AuthenticatedTransport> Client<T> {
    /// Bind an observation to this owner's actual pinned HTTPS transport origin.
    /// Compare it with the consumer's original configured trust origin before
    /// making the fresh call; never infer origin from response metadata.
    pub fn authenticated_origin(&self) -> Result<String> {
        self.transport.authenticated_origin()
    }
    /// Return exactly the bounded whole resource; no recipient selector or
    /// descriptor reconstruction is accepted. This grants no account authority.
    pub async fn account_record_object(&mut self, expected_length: usize) -> Result<Vec<u8>> {
        record::expected_length(expected_length)?;
        self.transport.authenticated_origin()?;
        self.transport.account_record_object(expected_length).await
    }
}
