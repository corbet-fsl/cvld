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
mod account_record;
mod accounting;
mod community;
mod creation;
pub use creation::*;
mod roles;
pub use roles::*;
mod root_issuance;
pub use account_record::*;
pub use accounting::*;
pub use community::*;
pub use root_issuance::*;
mod enrollment;
pub use enrollment::*;
mod self_ban;
pub use self_ban::*;
mod step_up;
pub use step_up::*;
mod contacts;
pub use contacts::*;
mod payments;
pub use payments::*;

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
/// Whether a device facade may return this action's raw result to its shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAccess {
    Forward,
    Trusted,
}
#[derive(Clone, Copy)]
pub struct Action {
    pub name: &'static str,
    pub description: &'static str,
    pub access: Access,
    pub scope: Scope,
    pub effect: Effect,
    pub client_access: ClientAccess,
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
    ($( $(#[$attr:meta])* $name:ident($request:ty) -> $response:ty, $access:ident, $scope:ident, $effect:ident, $client:ident, $description:literal; )*) => {
        pub static ACTIONS: &[Action] = &[$(
            $(#[$attr])* Action { name: stringify!($name), description: $description,
                access: Access::$access, scope: Scope::$scope, effect: Effect::$effect,
                client_access: ClientAccess::$client,
                request: schema::<$request>, response: schema::<$response>, protocol: protocol::<$request, $response> },
        )*];
        pub fn router(door: Door) -> Router {
            let mut router = Router::new();
            $( $(#[$attr])* {
                let body_limit = door.request_body_limit(action(stringify!($name)).expect("registered action"));
                router = router.route(concat!("/v1/", stringify!($name)), post(
                    |State(door): State<Door>, request: Request| async move {
                        let action = action(stringify!($name)).expect("registered action");
                        let source = door.source_of_request(&request);
                        let _permit = door.admit_source(action, source).await?;
                        let ctx = door.authorize(action, request.headers()).await?;
                        let Json(request) = tokio::time::timeout(door.body_timeout(action), Json::<$request>::from_request(request, &())).await.map_err(Error::Invalid.redact())?.map_err(Error::Invalid.redact())?;
                        let _guard = door.request_guard(action).await;
                        let ctx = door.complete_context(action, ctx).await?;
                        let publication = door.publication(action, &ctx);
                        let response: $response = publication.run(crate::service::at(ctx.now, door.$name(ctx, request))).await?;
                        Ok::<_, Error>(Json(response))
                    }
                ).layer(DefaultBodyLimit::max(body_limit)));
            } )*
            let ohttp = door.ohttp().cloned();
            let router = account_record::router(router).layer(door.cors())
                .layer(axum::middleware::map_response(|mut response: axum::response::Response| async move {
                    response.headers_mut().insert(axum::http::header::CACHE_CONTROL,
                        axum::http::HeaderValue::from_static("no-store"));
                    response
                })).with_state(door);
            // The gateway sits outermost: it decrypts first, and everything
            // inside sees an ordinary request marked as arriving through it.
            #[cfg(feature = "ohttp")]
            let router = match ohttp {
                Some(gateway) => cblv::gateway::mount(router, gateway),
                None => router,
            };
            #[cfg(not(feature = "ohttp"))]
            let _ = ohttp;
            router
        }
    }
}

actions! {
    register_begin(RegisterStart) -> Ceremony, Public, Both, Record, Forward, "Begin UV-required passkey registration";
    register_finish(RegisterFinish) -> User, Public, Both, Record, Forward, "Verify and store the first passkey";
    global_initial_registration_continue(GlobalInitialRegistrationContinue) -> InitialCeremony, Public, Global, Record, Forward, "Bind creation provenance to the retained first wallet registration";
    initial_registration_begin(InitialRegistrationBegin) -> InitialCeremony, Public, Community, Record, Forward, "Begin first community registration with original creation provenance";
    community_creation_recipient(CreationRecipientRequest) -> CreationRecipient, Member, Community, Record, Forward, "Prepare original community creation for this registered recipient";
    community_creation_initialize(CommunityCreationRequest) -> CommunityCreationInvitation, Root, Global, Record, Forward, "Initialize an explicitly linked community with its original first Root entitlement";
    community_founder_issue(CommunityCreationRequest) -> CommunityCreationInvitation, Root, Global, Record, Forward, "Issue the original FounderAdmin entitlement for a distinct registered founder of an explicitly linked community";
    initial_creation(Empty) -> InitialCreationResponse, Member, Both, Check, Forward, "Read this current passkey's original enrollment provenance";
    initial_publication_bind(InitialPublicationBind) -> InitialCreationResponse, Member, Both, Record, Forward, "Bind one original publication to this current passkey's initial enrollment";
    login_begin(LoginStart) -> Ceremony, Public, Both, Check, Forward, "Begin credential-first passkey authentication";
    login_discoverable_begin(Empty) -> DiscoverableCeremony, Public, Both, Check, Forward, "Begin usernameless sign-in with a synced passkey";
    login_finish(LoginFinish) -> Session, Public, Both, Record, Trusted, "Verify user and counter; create an ephemeral session";
    logout(Empty) -> Empty, Authenticated, Both, Check, Forward, "End this ephemeral session";
    member_role(Empty) -> MemberRole, Member, Community, Check, Forward, "Read the current original local membership role";
    member_role_set(SetMemberRole) -> Empty, Admin, Community, Record, Forward, "Change a role under current garden membership authority";
    wallet_trust_feed(Empty) -> TrustFeed, Public, Global, Check, Forward, "Read the isolated wallet original trust snapshots";
    wallet_trust_changes(Since) -> Announcement, Public, Global, Check, Forward, "Read the isolated wallet whole-view revision hint";
    wallet_device_keys(Empty) -> DeviceKeys, Member, Global, Check, Forward, "Read this wallet member's current public device bindings";
    wallet_device_authorize(DeviceKey) -> DeviceKeys, Member, Global, Record, Forward, "Bind the wallet device to the exact authenticated passkey";
    global_public(Empty) -> GlobalPublic, Public, Global, Check, Forward, "Read authenticated global issuer material";
    contact_plan(ContactPlan) -> ContactPreview, Member, Global, Check, Forward, "Preview enabled contact verification costs without dispatch";
    contact_check(ContactCheck) -> ContactPreview, Member, Global, Check, Forward, "Preview one check of this RAM-held contact session";
    contact_execute(ContactExecute) -> ContactReceipt, Member, Global, Record, Forward, "Explicitly authorize the exact prepared contact cost preview";
    contact_status(ContactOperation) -> ContactReceipt, Member, Global, Check, Forward, "Read the minimal outcome and reserved contact exposure";
    contact_accept(ContactOperation) -> ContactAcceptance, Member, Global, Record, Forward, "Accept a real typed contact fact through the global facade";
    contact_simulate(ContactSimulationRequest) -> ContactSimulationResponse, Member, Global, Check, Forward, "Simulate dummy contact planning locally without providers or credentials";
    passport_challenge(Empty) -> Bytes, Member, Global, Record, Forward, "Reserve a blind passport issuance challenge";
    passport_issue(PassportIssue) -> Bytes, Member, Global, Record, Forward, "Issue a blind passport after global policy checks";
    global_self_ban_begin(Empty) -> SelfBanChallenge, Member, Global, Check, Forward, "Confirm permanent global self-ban with a fresh passkey ceremony";
    global_self_ban_finish(SelfBanConfirmation) -> Empty, Member, Global, Record, Forward, "Permanently suspend this authenticated global account; no recovery";
    global_self_ban_status(Empty) -> SelfBanStatus, Member, Global, Check, Forward, "Read this authenticated wallet's permanent self-ban outcome";
    community_self_ban_begin(Empty) -> SelfBanChallenge, Member, Community, Check, Forward, "Confirm permanent community self-ban with a fresh passkey ceremony";
    community_self_ban_finish(SelfBanConfirmation) -> Empty, Member, Community, Record, Forward, "Permanently end this membership; no recovery or operator override";
    community_self_ban_status_begin(Empty) -> SelfBanStatusChallenge, Public, Community, Check, Forward, "Begin passkey authentication solely to inspect your own self-ban outcome";
    community_self_ban_status_finish(SelfBanConfirmation) -> SelfBanStatus, Public, Community, Record, Forward, "Inspect your own permanent self-ban with fresh UV; never restore access";
    presentation_challenge(Empty) -> PresentationChallenge, Public, Community, Record, Forward, "Begin a signed community passport presentation";
    root_board_issue_begin(Empty) -> RootBoardIssueChallenge, Admin, Community, Record, Forward, "Begin source-authorized blind root credential issuance";
    root_board_issue_finish(RootBoardIssueFinish) -> Bytes, Admin, Community, Record, Forward, "Complete same-holder blind root credential issuance";
    lobby(Empty) -> Lobby, Member, Community, Check, Forward, "Read enrolment and missing requirements";
    payment_offer(Empty) -> PaymentOffer, Member, Community, Check, Forward, "Read the configured original x402 offer and requested access";
    payment_plan(PaymentPlan) -> PaymentPreview, Member, Community, Check, Forward, "Preview the exact paid-access operation without provider calls";
    payment_execute(PaymentExecute) -> PaymentReceipt, Member, Community, Record, Forward, "Explicitly execute the exact prepared x402 settlement";
    payment_status(PaymentOperation) -> PaymentReceipt, Member, Community, Check, Forward, "Read only this member's minimal payment outcome";
    payment_accept(PaymentOperation) -> PaymentReceipt, Member, Community, Record, Forward, "Accept genuine paid access through the community gate owner";
    payment_simulate(PaymentSimulationRequest) -> PaymentSimulationResponse, Member, Community, Check, Forward, "Simulate dummy payment planning locally without provider I/O";
    handle_available(Handle) -> Available, Public, Community, Check, Forward, "Check a community handle";
    handle_reserve(Handle) -> Lobby, Member, Community, Record, Forward, "Reserve a community handle";
    gate_voucher(Voucher) -> Lobby, Member, Community, Record, Forward, "Verify a member-bound voucher";
    gate_withdraw(Withdraw) -> CredentialResponse, Member, Community, Record, Forward, "Withdraw a retained community gate";
    credential_issue(CredentialRequest) -> CredentialResponse, Member, Community, Record, Forward, "Present a passport and request admission or renewal";
    account_credential_issue(AccountCredentialRequest) -> AccountCredentialResponse, Member, Community, Record, Forward, "Request the original account grant from the same full admission decision";
    account(AccountRequest) -> AccountResponse, Member, Community, Record, Forward, "Forward this admitted member's original account operation";
    account_enroll(AccountEnrollmentRequest) -> AccountEnrollmentResponse, Member, Community, Record, Forward, "Enroll this member's signed account delegation in the original registry";
    account_checkpoint(AccountCheckpointRequest) -> AccountCheckpointResponse, Public, Community, Record, Forward, "Publish the current common enrollment roster or read an installed historical slot";
    account_record(Empty) -> AccountRecordResource, Public, Community, Check, Forward, "Read the fixed common record resource link";
    pin_set(PinRequest) -> PinResponse, Member, Community, Record, Forward, "Seal an initial profile fingerprint";
    pin_get(Field) -> PinResponse, Member, Community, Check, Forward, "Read a sealed fingerprint";
    pin_change(PinChange) -> PinResponse, Member, Community, Record, Forward, "Change a fingerprint using spent-token evidence";
    step_up_begin(StepUpStart) -> StepUpChallenge, Authenticated, Both, Check, Forward, "Begin a fresh user-verifying passkey assertion bound to one passkey, device or revocation action";
    passkey_list(Empty) -> PasskeyList, Authenticated, Both, Check, Forward, "List this account's passkeys and revocation status";
    passkey_certificate(Empty) -> PasskeyCertificateResponse, Member, Both, Check, Forward, "Certify the current registered passkey for original lineage assertions";
    passkey_add(AddPasskeyRequest) -> AddedPasskey, Authenticated, Both, Record, Forward, "Register another UV-required passkey for this account";
    passkey_revoke(RevokePasskey) -> Empty, Authenticated, Both, Record, Forward, "Revoke one of this account's passkeys";
    device_authorize(DeviceKey) -> DeviceKeys, Member, Community, Record, Forward, "Authorize the lineage device key with this live passkey";
    device_keys(Empty) -> DeviceKeys, Member, Community, Check, Forward, "Read current passkey-authorized signing keys";
    setting_set(Setting) -> TrustFeed, Admin, Community, Record, Forward, "Edit a community setting";
    platform_set(PlatformSetting) -> TrustFeed, Root, Community, Record, Forward, "Edit a platform setting or force switch";
    schema_check(SchemaRequest) -> SchemaChanges, Admin, Community, Check, Forward, "Classify profile schema changes";
    schema_set(SchemaRequest) -> TrustFeed, Admin, Community, Record, Forward, "Publish a profile schema";
    trust_feed(Empty) -> TrustFeed, Public, Community, Check, Forward, "Read signed public trust snapshots";
    trust_changes(Since) -> Announcement, Public, Community, Check, Forward, "Wait for a public revision announcement";
    #[cfg(feature = "development-gate")]
    development_gate(Empty) -> Empty, Member, Global, Record, Forward, "Pass the development-only synthetic uniqueness gate";
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
                (
                    "x-client-access",
                    format!("{:?}", action.client_access).to_lowercase(),
                ),
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
    account_record::declare(&mut paths, &error_response);
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
