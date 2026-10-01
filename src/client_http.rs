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
        super::origin(&base, &host)?;
        let client = reqwest::Client::builder()
            .user_agent("cvld-client")
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Unavailable)?;
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
        let call = call.build().map_err(|_| Error::Invalid)?;
        let mut response = self
            .client
            .execute(call)
            .await
            .map_err(|_| Error::Reconcile)?;
        let status = response.status().as_u16();
        const LIMIT: usize = 16 * 1024 * 1024;
        if response
            .content_length()
            .is_some_and(|size| size > LIMIT as u64)
        {
            return Err(Error::Reconcile);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Reconcile)? {
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
        self.call(name, request).await
    }
}
