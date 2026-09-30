use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    #[error("invalid request")]
    Invalid,
    #[error("authentication required")]
    Unauthorized,
    #[error("action forbidden")]
    Forbidden,
    #[error("wrong host or service")]
    WrongHost,
    #[error("request throttled")]
    Throttled,
    #[error("operation refused")]
    Refused,
    #[error("service unavailable")]
    Unavailable,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub error: Error,
}
pub type Result<T> = std::result::Result<T, Error>;
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::WrongHost => StatusCode::MISDIRECTED_REQUEST,
            Self::Throttled => StatusCode::TOO_MANY_REQUESTS,
            Self::Refused => StatusCode::CONFLICT,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(ErrorBody { error: self })).into_response()
    }
}
