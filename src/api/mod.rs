//! The single action definition drives every transport and generated schema.
use crate::{error::Error, service::Door};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
mod community;
pub use community::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Member,
    Admin,
    Root,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Public,
    Authenticated,
    Member,
    Admin,
    Root,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Both,
    Global,
    Community,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Check,
    Record,
}
#[derive(Clone, Copy)]
pub struct Action {
    pub name: &'static str,
    pub description: &'static str,
    pub access: Access,
    pub scope: Scope,
    pub effect: Effect,
    pub request: fn() -> Value,
    pub response: fn() -> Value,
    protocol: fn() -> Protocol,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Empty {}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterStart {
    /// Required for an operator; never a role supplied by the caller.
    pub bootstrap: Option<String>,
    /// Community-only, one-use passport presentation.
    pub passport: Option<PresentationInput>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Ceremony {
    pub ceremony: String,
    pub user: String,
    pub options: Value,
}
/// A usernameless challenge; identity is returned only after verification.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoverableCeremony {
    pub ceremony: String,
    pub options: Value,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinish {
    pub ceremony: String,
    #[schema(value_type = std::collections::BTreeMap<String, Value>, additional_properties = true)]
    pub credential: ckyh::RegisterPublicKeyCredential,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub user: String,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PresentationInput {
    pub challenge: String,
    pub proof: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginStart {
    pub user: String,
    pub credential: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginFinish {
    pub ceremony: String,
    #[schema(value_type = std::collections::BTreeMap<String, Value>, additional_properties = true)]
    pub credential: ckyh::PublicKeyCredential,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub token: String,
    pub user: String,
    pub role: Role,
    pub expires: u64,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Bytes {
    pub bytes: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PassportIssue {
    pub challenge: Vec<u8>,
    pub request: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GlobalPublic {
    pub key_ring: Vec<u8>,
    pub issuer: Vec<u8>,
    pub status: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Suspend {
    pub user: String,
    pub until: u64,
}

struct Protocol {
    request: utoipa::openapi::request_body::RequestBody,
    response: utoipa::openapi::Response,
    components: Vec<(String, utoipa::openapi::RefOr<utoipa::openapi::Schema>)>,
}
fn protocol<I: ToSchema, O: ToSchema>() -> Protocol {
    use utoipa::openapi::{Content, Required, Response, request_body::RequestBody};
    let mut components = Vec::new();
    I::schemas(&mut components);
    O::schemas(&mut components);
    let mut request = RequestBody::new();
    request.required = Some(Required::True);
    request.content.insert(
        "application/json".into(),
        Content::new(Some(I::schema())).into(),
    );
    let mut response = Response::new("Success");
    response.content.insert(
        "application/json".into(),
        Content::new(Some(O::schema())).into(),
    );
    Protocol {
        request,
        response,
        components,
    }
}

fn schema<T: ToSchema>() -> Value {
    let mut schemas = Vec::new();
    T::schemas(&mut schemas);
    let mut root = serde_json::to_value(T::schema()).expect("Rust schema is serializable");
    let defs: serde_json::Map<String, Value> = schemas
        .into_iter()
        .map(|(name, schema)| {
            (
                name,
                serde_json::to_value(schema).expect("Rust schema is serializable"),
            )
        })
        .collect();
    // OpenAPI components and MCP use the same self-contained JSON Schema.
    fn refs(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(reference)) = map.get_mut("$ref") {
                    *reference = reference.replace("#/components/schemas/", "#/$defs/");
                }
                for value in map.values_mut() {
                    refs(value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    refs(value);
                }
            }
            _ => {}
        }
    }
    if !defs.is_empty() {
        root["$defs"] = Value::Object(defs);
    }
    refs(&mut root);
    // Door actions exchange objects, including tagged unions of object variants.
    // MCP requires the top-level input and output schema type to be explicit.
    root["type"] = Value::String("object".into());
    root
}

macro_rules! actions {
    ($( $(#[$attr:meta])* $name:ident($request:ty) -> $response:ty, $access:ident, $scope:ident, $effect:ident, $description:literal; )*) => {
        pub static ACTIONS: &[Action] = &[$(
            $(#[$attr])* Action { name: stringify!($name), description: $description,
                access: Access::$access, scope: Scope::$scope, effect: Effect::$effect,
                request: schema::<$request>, response: schema::<$response>, protocol: protocol::<$request, $response> },
        )*];
        pub fn router(door: Door) -> Router {
            let mut router = Router::new();
            $( $(#[$attr])* {
                router = router.route(concat!("/v1/", stringify!($name)), post(
                    |State(door): State<Door>, request: Request| async move {
                        let action = action(stringify!($name)).expect("registered action");
                        let _permit = door.admit_request(action).await?;
                        let ctx = door.authorize(action, request.headers()).await?;
                        let Json(request) = tokio::time::timeout(std::time::Duration::from_secs(10), Json::<$request>::from_request(request, &())).await.map_err(|_| Error::Invalid)?.map_err(|_| Error::Invalid)?;
                        let _guard = door.request_guard(action).await;
                        let ctx = door.complete_context(action, ctx).await?;
                        let response: $response = crate::service::at(ctx.now, door.$name(ctx, request)).await?;
                        Ok::<_, Error>(Json(response))
                    }
                ));
            } )*
            router.layer(DefaultBodyLimit::max(256 * 1024)).layer(door.cors())
                .layer(axum::middleware::map_response(|mut response: axum::response::Response| async move {
                    response.headers_mut().insert(axum::http::header::CACHE_CONTROL,
                        axum::http::HeaderValue::from_static("no-store"));
                    response
                })).with_state(door)
        }
    }
}

actions! {
    register_begin(RegisterStart) -> Ceremony, Public, Both, Record, "Begin UV-required passkey registration";
    register_finish(RegisterFinish) -> User, Public, Both, Record, "Verify and store the first passkey";
    login_begin(LoginStart) -> Ceremony, Public, Both, Check, "Begin credential-first passkey authentication";
    login_discoverable_begin(Empty) -> DiscoverableCeremony, Public, Both, Check, "Begin usernameless sign-in with a synced passkey";
    login_finish(LoginFinish) -> Session, Public, Both, Record, "Verify user and counter; create an ephemeral session";
    logout(Empty) -> Empty, Authenticated, Both, Check, "End this ephemeral session";
    global_public(Empty) -> GlobalPublic, Public, Global, Check, "Read authenticated global issuer material";
    passport_challenge(Empty) -> Bytes, Member, Global, Record, "Reserve a blind passport issuance challenge";
    passport_issue(PassportIssue) -> Bytes, Member, Global, Record, "Issue a blind passport after global policy checks";
    presentation_challenge(Empty) -> PresentationChallenge, Public, Community, Record, "Begin a signed community passport presentation";
    lobby(Empty) -> Lobby, Member, Community, Check, "Read enrolment and missing requirements";
    handle_available(Handle) -> Available, Public, Community, Check, "Check a community handle";
    handle_reserve(Handle) -> Lobby, Member, Community, Record, "Reserve a community handle";
    gate_voucher(Voucher) -> Lobby, Member, Community, Record, "Verify a member-bound voucher";
    gate_withdraw(Withdraw) -> CredentialResponse, Member, Community, Record, "Withdraw a retained community gate";
    credential_issue(CredentialRequest) -> CredentialResponse, Member, Community, Record, "Present a passport and request admission or renewal";
    pin_set(PinRequest) -> PinResponse, Member, Community, Record, "Seal an initial profile fingerprint";
    pin_get(Field) -> PinResponse, Member, Community, Check, "Read a sealed fingerprint";
    pin_change(PinChange) -> PinResponse, Member, Community, Record, "Change a fingerprint using spent-token evidence";
    passkey_add(AddPasskey) -> AddedPasskey, Member, Community, Record, "Register another UV-required passkey for this membership";
    passkey_revoke(RevokePasskey) -> Empty, Member, Community, Record, "Revoke a community passkey";
    device_authorize(DeviceKey) -> DeviceKeys, Member, Community, Record, "Authorize the lineage device key with this live passkey";
    device_keys(Empty) -> DeviceKeys, Member, Community, Check, "Read current passkey-authorized signing keys";
    setting_set(Setting) -> TrustFeed, Admin, Community, Record, "Edit a community setting";
    platform_set(PlatformSetting) -> TrustFeed, Root, Community, Record, "Edit a platform setting or force switch";
    schema_check(SchemaRequest) -> SchemaChanges, Admin, Community, Check, "Classify profile schema changes";
    schema_set(SchemaRequest) -> TrustFeed, Admin, Community, Record, "Publish a profile schema";
    trust_feed(Empty) -> TrustFeed, Public, Community, Check, "Read signed public trust snapshots";
    trust_changes(Since) -> Announcement, Public, Community, Check, "Wait for a public revision announcement";
    global_warn(User) -> Empty, Root, Global, Record, "Record the warning preceding temporary suspension";
    global_suspend(Suspend) -> Empty, Root, Global, Record, "Temporarily suspend and advance the global epoch";
    #[cfg(feature = "development-gate")]
    development_gate(Empty) -> Empty, Member, Global, Record, "Pass the development-only synthetic uniqueness gate";
}

pub fn action(name: &str) -> Option<&'static Action> {
    ACTIONS.iter().find(|a| a.name == name)
}
pub fn openapi() -> utoipa::openapi::OpenApi {
    use utoipa::openapi::{
        Components, Info, OpenApi, Paths, Response,
        path::{HttpMethod, Operation, PathItem},
        security::{Http, HttpAuthScheme, SecurityRequirement, SecurityScheme},
    };
    let mut components = Components::new();
    components.security_schemes.insert(
        "session".into(),
        SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)).into(),
    );
    let mut error_schemas = Vec::new();
    crate::error::ErrorBody::schemas(&mut error_schemas);
    components.schemas.extend(error_schemas);
    let mut error_response = Response::new("Fixed redacted error category");
    error_response.content.insert(
        "application/json".into(),
        utoipa::openapi::Content::new(Some(
            <crate::error::ErrorBody as utoipa::PartialSchema>::schema(),
        ))
        .into(),
    );
    let mut paths = Paths::new();
    for action in ACTIONS {
        let protocol = (action.protocol)();
        components.schemas.extend(protocol.components);
        let mut operation = Operation::new();
        operation.operation_id = Some(action.name.into());
        operation.summary = Some(action.description.into());
        operation.request_body = Some(protocol.request.into());
        operation
            .responses
            .responses
            .insert("200".into(), protocol.response.into());
        operation
            .responses
            .responses
            .insert("default".into(), error_response.clone().into());
        operation.extensions = Some(
            [
                ("x-role", format!("{:?}", action.access).to_lowercase()),
                ("x-effect", format!("{:?}", action.effect).to_lowercase()),
                ("x-scope", format!("{:?}", action.scope).to_lowercase()),
            ]
            .into_iter()
            .collect(),
        );
        operation.security = Some(if action.access == Access::Public {
            Vec::new()
        } else {
            vec![SecurityRequirement::new(
                "session",
                std::iter::empty::<&str>(),
            )]
        });
        paths.paths.insert(
            format!("/v1/{}", action.name),
            PathItem::new(HttpMethod::Post, operation),
        );
    }
    let mut document = OpenApi::new(Info::new("cvld", "0.2.0"), paths);
    document.components = Some(components);
    document
}
/// Canonical object ordering makes generated documents reproducible.
pub fn openapi_json() -> String {
    let mut value = serde_json::to_value(openapi()).expect("OpenAPI is serializable");
    value.sort_all_objects();
    serde_json::to_string_pretty(&value).expect("OpenAPI is serializable")
}
