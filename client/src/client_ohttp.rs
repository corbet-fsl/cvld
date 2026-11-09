//! Door client through Oblivious HTTP: every call is encapsulated to the
//! gateway key by the shared [`cblv::client::Wire`]. The relay sees the sender
//! but only ciphertext; the gateway sees the call but not the sender. The
//! inner authority is the door host, which the server validates as before.
use super::Transport;
use crate::error::{Error, Result};
use cblv::{client::Wire, codec};
use serde_json::Value;

const LIMIT: usize = 16 * 1024 * 1024;

pub struct OhttpClient<W> {
    wire: W,
    host: String,
    token: Option<zeroize::Zeroizing<String>>,
}

impl<W: Wire> OhttpClient<W> {
    /// `host` is the door's exact HTTPS host (the inner authority).
    pub fn new(wire: W, host: String, token: Option<String>) -> Result<Self> {
        super::origin(&format!("https://{host}"), &host)?;
        Ok(Self {
            wire,
            host,
            token: token.map(zeroize::Zeroizing::new),
        })
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(&str, Vec<u8>)>,
        body: Vec<u8>,
    ) -> codec::Request {
        codec::Request {
            method: method.as_bytes().to_vec(),
            authority: self.host.clone().into_bytes(),
            path: path.as_bytes().to_vec(),
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.as_bytes().to_vec(), value))
                .collect(),
            body,
        }
    }

    pub async fn call(&self, name: &str, request: Value) -> Result<Value> {
        // The committed contract of this build equals the live registry; cvld's
        // `contract_equals_live_registry` tests enforce it in every feature set.
        if super::action(name).is_none() {
            return Err(Error::Invalid);
        }
        let body = serde_json::to_vec(&request).map_err(Error::Invalid.redact())?;
        let mut headers = vec![("content-type", b"application/json".to_vec())];
        if let Some(token) = &self.token {
            headers.push((
                "authorization",
                format!("Bearer {}", token.as_str()).into_bytes(),
            ));
        }
        let response = self
            .wire
            .exchange(self.request("POST", &format!("/v1/{name}"), headers, body))
            .await
            .map_err(Error::Reconcile.redact())?;
        if response.body.len() > LIMIT {
            return Err(Error::Reconcile);
        }
        let body = zeroize::Zeroizing::new(response.body);
        super::decode_response(name, response.status, &body)
    }
}

impl<W: Wire> Transport for OhttpClient<W> {
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

impl<W: Wire> super::SessionTransport for OhttpClient<W> {
    fn adopt_session(&mut self, token: zeroize::Zeroizing<String>) {
        self.token = Some(token);
    }
}

impl<W: Wire> super::sealed::Authenticated for OhttpClient<W> {}
impl<W: Wire> super::AuthenticatedTransport for OhttpClient<W> {
    fn authenticated_origin(&self) -> Result<String> {
        let url = super::origin(&format!("https://{}", self.host), &self.host)?;
        Ok(url.origin().ascii_serialization())
    }

    async fn account_record_object(&mut self, expected_length: usize) -> Result<Vec<u8>> {
        super::record::expected_length(expected_length)?;
        self.authenticated_origin()?;
        // Anonymous common bytes: never send an account session to this route.
        let request = self.request(
            "GET",
            super::record::PATH,
            vec![("accept", b"application/octet-stream".to_vec())],
            Vec::new(),
        );
        let response = self
            .wire
            .exchange(request)
            .await
            .map_err(Error::Reconcile.redact())?;
        if response.body.len() > LIMIT {
            return Err(Error::Reconcile);
        }
        if response.status != 200 {
            return match super::decode_response("", response.status, &response.body) {
                Err(error) => Err(error),
                Ok(_) => Err(Error::Reconcile),
            };
        }
        let typed = response
            .headers
            .iter()
            .any(|(name, value)| name == b"content-type" && value == b"application/octet-stream");
        if !typed || response.body.len() != expected_length {
            return Err(Error::Reconcile);
        }
        Ok(response.body)
    }
}
