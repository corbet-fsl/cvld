#[cfg(feature = "server")]
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, thiserror::Error)]
#[cfg_attr(feature = "server", derive(ToSchema))]
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
    #[error("outcome unknown; reconcile current state before another operation")]
    Reconcile,
}
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub error: Error,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    /// The owner's original status for this redacted error category.
    pub fn http_status(self) -> u16 {
        match self {
            Self::Invalid => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::WrongHost => 421,
            Self::Throttled => 429,
            Self::Refused => 409,
            Self::Unavailable | Self::Reconcile => 503,
        }
    }
}
#[cfg(feature = "server")]
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.http_status()).expect("fixed valid HTTP status");
        (status, Json(ErrorBody { error: self })).into_response()
    }
}
