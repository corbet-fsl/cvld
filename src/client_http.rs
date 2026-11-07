//! Native HTTP adapter for the generated door contract.
use super::Transport;
use crate::error::{Error, Result};
use serde_json::Value;

#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    base: String,
    host: String,
    token: Option<zeroize::Zeroizing<String>>,
}
impl HttpClient {
    pub fn new(base: String, host: String, token: Option<String>) -> Result<Self> {
        Self::with_roots(base, host, token, &[])
    }

    /// Add explicit deployment trust roots while preserving normal TLS hostname,
    /// chain and certificate validation. These public DER certificates are trusted
    /// host configuration, never member request fields or an authentication grant.
    pub fn with_roots(
        base: String,
        host: String,
        token: Option<String>,
        roots: &[Vec<u8>],
    ) -> Result<Self> {
        super::origin(&base, &host)?;
        super::install_crypto_provider();
        if roots.len() > 32
            || roots
                .iter()
                .any(|der| der.is_empty() || der.len() > 64 * 1024)
        {
            return Err(Error::Invalid);
        }
        let mut builder = reqwest::Client::builder()
            .user_agent("cvld-client")
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            // The service (hyper) closes a connection that sends no request head for 30 s,
            // idle keep-alive included. A pooled connection idle longer could be reused
            // just as the server drops it; that send fails as an unknown outcome
            // (Reconcile). Idle connections are therefore retired well before.
            .pool_idle_timeout(std::time::Duration::from_secs(20));
        for der in roots {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_der(der).map_err(Error::Invalid.redact())?,
            );
        }
        let client = builder.build().map_err(Error::Unavailable.redact())?;
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_owned(),
            host,
            token: token.map(zeroize::Zeroizing::new),
        })
    }
    pub async fn call(&self, name: &str, request: Value) -> Result<Value> {
        let known = {
            #[cfg(feature = "server")]
            {
                crate::api::action(name).is_some()
            }
            #[cfg(not(feature = "server"))]
            {
                super::action(name).is_some()
            }
        };
        if !known {
            return Err(Error::Invalid);
        }
        let mut call = self
            .client
            .post(format!("{}/v1/{name}", self.base))
            .header("host", &self.host)
            .json(&request);
        if let Some(token) = &self.token {
            call = call.bearer_auth(token.as_str());
        }
        // Builder errors occur before dispatch. Once execute begins, the server
        // may have committed even if transport, framing or decoding fails.
        let call = call.build().map_err(Error::Invalid.redact())?;
        let mut response = self
            .client
            .execute(call)
            .await
            .map_err(Error::Reconcile.redact())?;
        let status = response.status().as_u16();
        const LIMIT: usize = 16 * 1024 * 1024;
        if response
            .content_length()
            .is_some_and(|size| size > LIMIT as u64)
        {
            return Err(Error::Reconcile);
        }
        let mut body = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(Error::Reconcile.redact())? {
            if chunk.len() > LIMIT - body.len() {
                return Err(Error::Reconcile);
            }
            body.extend_from_slice(&chunk);
        }
        super::decode_response(name, status, &body)
    }
}

impl Transport for HttpClient {
    async fn send(&mut self, path: &str, request: Value) -> Result<Value> {
        let name = path.strip_prefix("/v1/").ok_or(Error::Invalid)?;
        let result = self.call(name, request).await;
        // A successful logout ended the server session: stop presenting its bearer, which the owner
        // refuses as an unknown session even on public routes.
        if name == "logout" && result.is_ok() {
            self.token = None;
        }
        result
    }
}

impl super::SessionTransport for HttpClient {
    fn adopt_session(&mut self, token: zeroize::Zeroizing<String>) {
        self.token = Some(token);
    }
}

impl super::sealed::Authenticated for HttpClient {}
impl super::AuthenticatedTransport for HttpClient {
    fn authenticated_origin(&self) -> Result<String> {
        let url = super::origin(&self.base, &self.host)?;
        if url.scheme() != "https" {
            return Err(Error::WrongHost);
        }
        Ok(url.origin().ascii_serialization())
    }
    async fn account_record_object(&mut self, expected_length: usize) -> Result<Vec<u8>> {
        super::record::expected_length(expected_length)?;
        self.authenticated_origin()?;
        // Anonymous common bytes: never send an account session to this route.
        let request = self
            .client
            .get(format!("{}{}", self.base, super::record::PATH))
            .header("host", &self.host)
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .build()
            .map_err(Error::Invalid.redact())?;
        let mut response = self
            .client
            .execute(request)
            .await
            .map_err(Error::Reconcile.redact())?;
        if response.status().as_u16() != 200 {
            // Preserve the original redacted status contract on bounded errors.
            let status = response.status().as_u16();
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(Error::Reconcile.redact())? {
                if chunk.len() > 16 * 1024 * 1024 - bytes.len() {
                    return Err(Error::Reconcile);
                }
                bytes.extend_from_slice(&chunk);
            }
            return match super::decode_response("", status, &bytes) {
                Err(error) => Err(error),
                Ok(_) => Err(Error::Reconcile),
            };
        }
        if response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/octet-stream")
        {
            return Err(Error::Reconcile);
        }
        let length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .map(|value| value.to_str().map_err(Error::Reconcile.redact()))
            .transpose()?;
        super::record::content_length(length, expected_length)?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(Error::Reconcile.redact())? {
            if chunk.len() > expected_length - bytes.len() {
                return Err(Error::Reconcile);
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != expected_length {
            return Err(Error::Reconcile);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A real TLS handshake with a self-signed loopback certificate: no
    /// network, no name resolution, and the certificate is an explicit root
    /// of the product client.
    async fn tls_server() -> (SocketAddr, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "cvld-handshake");
        let cert = params.self_signed(&key).expect("self-signed");
        let der = cert.der().to_vec();
        let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone().into()],
            tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let addr = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut stream = acceptor.accept(stream).await.expect("handshake");
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await.expect("request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                )
                .await
                .expect("response");
            stream.shutdown().await.expect("close");
        });
        (addr, der)
    }

    #[tokio::test]
    async fn the_product_client_completes_a_real_tls_handshake() {
        let (addr, der) = tls_server().await;
        let base = format!("https://127.0.0.1:{}", addr.port());
        let http =
            HttpClient::with_roots(base.clone(), "127.0.0.1".into(), None, &[der]).expect("client");
        let response = http
            .client
            .get(format!("{base}/probe"))
            .send()
            .await
            .expect("request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.expect("body"), "ok");
    }
}
