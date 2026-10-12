//! Honest binary-resource projection beside the single JSON action registry.
use super::*;
use axum::{
    extract::{OriginalUri, State},
    http::{HeaderMap, header},
    response::IntoResponse,
    routing::get,
};

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountRecordResource {
    /// Fixed relative resource path. This link carries no descriptor authority.
    pub path: String,
    pub media_type: String,
}

pub(super) fn router(router: Router<Door>) -> Router<Door> {
    router.route(
        crate::client::record::PATH,
        get(
            |State(door): State<Door>,
             OriginalUri(uri): OriginalUri,
             peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
             headers: HeaderMap| async move {
                let action = action("account_record").expect("registered common resource metadata");
                let source = crate::bucket::source_of(peer.map(|info| info.0.ip()), &headers);
                let _permit = door.admit_request(action, source).await?;
                let ctx = door.authorize(action, &headers).await?;
                if uri.query().is_some() {
                    return Err(Error::Invalid);
                }
                let _guard = door.request_guard(action).await;
                let ctx = door.complete_context(action, ctx).await?;
                let publication = door.publication(action, &ctx);
                let bytes = publication
                    .run(crate::service::at(ctx.now, door.account_record_bytes(ctx)))
                    .await?;
                Ok::<_, Error>(
                    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response(),
                )
            },
        ),
    )
}

pub(super) fn declare(paths: &mut utoipa::openapi::Paths, error: &utoipa::openapi::Response) {
    use utoipa::openapi::{
        Content, Response,
        path::{HttpMethod, Operation, PathItem},
        schema::{KnownFormat, ObjectBuilder, SchemaFormat, Type},
    };
    let mut operation = Operation::new();
    operation.operation_id = Some("account_record_object".into());
    operation.summary = Some("Download the same whole authenticated common record object".into());
    operation.security = Some(Vec::new());
    operation.extensions = Some(
        [
            ("x-role", "public"),
            ("x-scope", "community"),
            ("x-effect", "check"),
            ("x-cvld-resource", crate::client::record::RESOURCE),
        ]
        .into_iter()
        .collect(),
    );
    let mut response = Response::new(
        "Whole original owner object; verify against the current signed Epoch descriptor",
    );
    response.content.insert(
        "application/octet-stream".into(),
        Content::new(Some(
            ObjectBuilder::new()
                .schema_type(Type::String)
                .format(Some(SchemaFormat::KnownFormat(KnownFormat::Binary))),
        ))
        .into(),
    );
    operation
        .responses
        .responses
        .insert("200".into(), response.into());
    operation
        .responses
        .responses
        .insert("default".into(), error.clone().into());
    paths.paths.insert(
        crate::client::record::PATH.into(),
        PathItem::new(HttpMethod::Get, operation),
    );
}
