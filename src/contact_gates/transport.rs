//! Fixed-endpoint TLS transport; no retries, redirects, proxy discovery or logs.
use super::{Error, Result};
use crate::service::Clock;
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

pub type PhoneFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<axum::http::Response<cphn::Private>, cphn::Error>,
            > + Send
            + 'a,
    >,
>;
pub type MailboxFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<axum::http::Response<cmbx::Private>, cmbx::Error>,
            > + Send
            + 'a,
    >,
>;
/// Explicit trusted host HTTP boundary. The door never accepts this through its
/// JSON API. Inert implementations belong in tests and replace only external
/// HTTP, while original leaf request correlation and verification still run.
pub trait TrustedTransport: Send + Sync {
    fn mode(&self) -> cfbk::cost::Mode;
    fn phone(&self, request: axum::http::Request<cphn::Private>) -> PhoneFuture<'_>;
    fn mailbox(&self, request: axum::http::Request<cmbx::Private>) -> MailboxFuture<'_>;
}
/// Type erasure is limited to the external transport; it accepts no gate facts.
pub struct AnyTransport(Arc<dyn TrustedTransport>);
impl AnyTransport {
    pub fn new(transport: Arc<dyn TrustedTransport>) -> Self {
        Self(transport)
    }
}
impl cphn::Transport for AnyTransport {
    fn mode(&self) -> cfbk::cost::Mode {
        self.0.mode()
    }
    async fn send(
        &self,
        request: axum::http::Request<cphn::Private>,
    ) -> std::result::Result<axum::http::Response<cphn::Private>, cphn::Error> {
        self.0.phone(request).await
    }
}
impl cmbx::Transport for AnyTransport {
    fn mode(&self) -> cfbk::cost::Mode {
        self.0.mode()
    }
    async fn send(
        &self,
        request: axum::http::Request<cmbx::Private>,
    ) -> std::result::Result<axum::http::Response<cmbx::Private>, cmbx::Error> {
        self.0.mailbox(request).await
    }
}

pub struct HttpTransport {
    client: reqwest::Client,
    clock: Arc<dyn Clock>,
}
impl HttpTransport {
    pub fn new(clock: Arc<dyn Clock>, timeout_seconds: u64) -> Result<Self> {
        if timeout_seconds == 0
            || std::time::Instant::now()
                .checked_add(Duration::from_secs(timeout_seconds))
                .is_none()
        {
            return Err(Error::Configuration);
        }
        crate::client::install_crypto_provider();
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .timeout(Duration::from_secs(timeout_seconds))
            .build()
            .map_err(|_| Error::Configuration)?;
        Ok(Self { client, clock })
    }
    async fn dispatch(
        &self,
        method: reqwest::Method,
        uri: &str,
        headers: reqwest::header::HeaderMap,
        body: &[u8],
        deadline: u64,
        floor: u64,
    ) -> Result<reqwest::Response> {
        let url = reqwest::Url::parse(uri).map_err(|_| Error::Configuration)?;
        let segments: Vec<_> = url.path_segments().ok_or(Error::Configuration)?.collect();
        if method != reqwest::Method::POST
            || url.scheme() != "https"
            || url.host_str() != Some("verify.twilio.com")
            || url.port().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || segments.len() != 4
            || segments[0] != "v2"
            || segments[1] != "Services"
            || !matches!(segments[3], "Verifications" | "VerificationCheck")
            || !segments[2].starts_with("VA")
            || segments[2].len() != 34
            || !segments[2][2..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::Configuration);
        }
        let request = self
            .client
            .request(method, url)
            .headers(headers)
            .body(body.to_vec())
            .build()
            .map_err(|_| Error::Configuration)?;
        // This is the final synchronous observation before reqwest receives the
        // request. Its internal DNS/TLS wait is bounded by the monotonic timeout;
        // no claim is made that an external provider checks our wall clock.
        let now = self.clock.now();
        if now < floor || now >= deadline {
            return Err(Error::Expired);
        }
        self.client
            .execute(request)
            .await
            .map_err(|_| Error::Uncertain)
    }
}

macro_rules! leaf_transport {
    ($leaf:ident) => {
        impl $leaf::Transport for HttpTransport {
            fn mode(&self) -> cfbk::cost::Mode {
                cfbk::cost::Mode::Production
            }
            async fn send(
                &self,
                request: axum::http::Request<$leaf::Private>,
            ) -> std::result::Result<axum::http::Response<$leaf::Private>, $leaf::Error> {
                let deadline = request
                    .extensions()
                    .get::<$leaf::DispatchDeadline>()
                    .ok_or($leaf::Error::NotDispatched)?
                    .valid_until;
                let started = self.clock.now();
                if started >= deadline {
                    return Err($leaf::Error::NotDispatched);
                }
                let (parts, body) = request.into_parts();
                let mut response = self
                    .dispatch(
                        parts.method,
                        &parts.uri.to_string(),
                        parts.headers,
                        body.expose(),
                        deadline,
                        started,
                    )
                    .await
                    .map_err(|error| match error {
                        Error::Expired | Error::Configuration => $leaf::Error::NotDispatched,
                        _ => $leaf::Error::Uncertain,
                    })?;
                if response
                    .content_length()
                    .is_some_and(|length| length > 65536)
                {
                    return Err($leaf::Error::Uncertain);
                }
                let status = response.status();
                let mut bytes = Zeroizing::new(Vec::new());
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|_| $leaf::Error::Uncertain)?
                {
                    if chunk.len() > 65536 - bytes.len() {
                        return Err($leaf::Error::Uncertain);
                    }
                    bytes.extend_from_slice(&chunk);
                }
                if self.clock.now() < started {
                    return Err($leaf::Error::Uncertain);
                }
                let mut result =
                    axum::http::Response::new($leaf::Private::new(std::mem::take(&mut *bytes)));
                *result.status_mut() = status;
                Ok(result)
            }
        }
    };
}
leaf_transport!(cphn);
leaf_transport!(cmbx);

impl TrustedTransport for HttpTransport {
    fn mode(&self) -> cfbk::cost::Mode {
        cfbk::cost::Mode::Production
    }
    fn phone(&self, request: axum::http::Request<cphn::Private>) -> PhoneFuture<'_> {
        Box::pin(cphn::Transport::send(self, request))
    }
    fn mailbox(&self, request: axum::http::Request<cmbx::Private>) -> MailboxFuture<'_> {
        Box::pin(cmbx::Transport::send(self, request))
    }
}
