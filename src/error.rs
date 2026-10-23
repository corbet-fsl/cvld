#[cfg(feature = "server")]
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[cfg_attr(feature = "server", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Error {
    #[error("invalid request")]
    Invalid,
    #[error("authentication required")]
    Unauthorized,
    #[error("action forbidden")]
    Forbidden,
    #[error("held in lobby")]
    HeldInLobby,
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
    /// Refused before commitment because the signed request's window had elapsed;
    /// nothing was written. On the wire it is `refused` with the reason `expired`
    /// (see `ErrorBody`), never an error code of its own.
    #[error("operation refused: request window elapsed")]
    #[serde(skip)]
    Expired,
    /// Client side only, never a server answer: the device clock differs from the server's
    /// time by more than the clock-skew tolerance. The user checks the device time.
    #[error("the device clock differs from the server's; check the device time")]
    Clock,
}

/// Typed reason of a `refused` error. The only reason a client may act on
/// without reconciling: nothing was written, so it may prepare a fresh request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// The signed request's acceptance window elapsed before commitment.
    Expired,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub error: Error,
    /// Present only on `refused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<RefusalReason>,
}

impl From<Error> for ErrorBody {
    fn from(error: Error) -> Self {
        match error {
            Error::Expired => Self {
                error: Error::Refused,
                reason: Some(RefusalReason::Expired),
            },
            error => Self {
                error,
                reason: None,
            },
        }
    }
}

impl ErrorBody {
    /// The error this body names; a reason on anything but `refused` is malformed.
    pub fn error(&self) -> Option<Error> {
        match (self.error, self.reason) {
            (Error::Refused, Some(RefusalReason::Expired)) => Some(Error::Expired),
            (Error::Expired, _) | (_, Some(_)) => None,
            (error, None) => Some(error),
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    /// Discard a dependency error without formatting or forwarding its private data.
    /// The call site still chooses the exact public error category.
    pub fn redact<T>(self) -> impl FnOnce(T) -> Self {
        move |_| self
    }

    /// The owner's original status for this redacted error category.
    pub fn http_status(self) -> u16 {
        match self {
            Self::Invalid | Self::Clock => 400,
            Self::Unauthorized => 401,
            Self::Forbidden | Self::HeldInLobby => 403,
            Self::WrongHost => 421,
            Self::Throttled => 429,
            Self::Refused | Self::Expired => 409,
            Self::Unavailable | Self::Reconcile => 503,
        }
    }
}
#[cfg(feature = "server")]
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.http_status()).expect("fixed valid HTTP status");
        (status, Json(ErrorBody::from(self))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_expiry_is_409_refused_with_the_reason_expired() {
        assert_eq!(Error::Expired.http_status(), 409);
        let wire = serde_json::to_value(ErrorBody::from(Error::Expired)).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({"error": "refused", "reason": "expired"})
        );
        let body: ErrorBody = serde_json::from_value(wire).unwrap();
        assert_eq!(body.error(), Some(Error::Expired));
        // A plain refusal carries no reason and stays a plain refusal.
        let plain = serde_json::to_value(ErrorBody::from(Error::Refused)).unwrap();
        assert_eq!(plain, serde_json::json!({"error": "refused"}));
        let body: ErrorBody = serde_json::from_value(plain).unwrap();
        assert_eq!(body.error(), Some(Error::Refused));
        // A reason on any other category, or the internal name on the wire, is malformed.
        let body: ErrorBody =
            serde_json::from_value(serde_json::json!({"error": "reconcile", "reason": "expired"}))
                .unwrap();
        assert_eq!(body.error(), None);
        assert!(
            serde_json::from_value::<ErrorBody>(serde_json::json!({"error": "expired"})).is_err()
        );
    }
}
