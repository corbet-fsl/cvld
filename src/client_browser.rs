//! Browser Fetch and Web Streams through maintained wasm-bindgen bindings.
use super::Transport;
use crate::error::{Error, Result};
use serde_json::Value;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

/// Origin-bound browser runtime. Authentication uses an explicit opaque session;
/// ambient cookies, redirects, referrers and cached replies are disabled.
#[derive(Clone)]
pub struct BrowserClient {
    base: String,
    token: Option<zeroize::Zeroizing<String>>,
}

impl BrowserClient {
    /// Bind the exact configured HTTPS origin. HTTP is limited to loopback tests.
    /// Browsers choose Host from the URL; the native fixture override is forbidden.
    pub fn new(base: String, host: String, token: Option<String>) -> Result<Self> {
        let url = super::origin(&base, &host)?;
        if url.host_str() != Some(host.as_str()) {
            return Err(Error::WrongHost);
        }
        Ok(Self {
            base: url.origin().ascii_serialization(),
            token: token.map(zeroize::Zeroizing::new),
        })
    }

    /// Dispatch once. Any failure after Fetch starts requires reconciliation.
    pub async fn call(&self, name: &str, input: Value) -> Result<Value> {
        let action = super::action(name).ok_or(Error::Invalid)?;
        let window = web_sys::window().ok_or(Error::Unavailable)?;
        let headers = web_sys::Headers::new().map_err(|_| Error::Invalid)?;
        headers
            .set("content-type", "application/json")
            .map_err(|_| Error::Invalid)?;
        if let Some(token) = &self.token {
            headers
                .set("authorization", &format!("Bearer {}", token.as_str()))
                .map_err(|_| Error::Invalid)?;
        }
        let controller = web_sys::AbortController::new().map_err(|_| Error::Unavailable)?;
        let cancellation = CancelOnDrop(controller.clone());
        let timeout = gloo_timers::callback::Timeout::new(30_000, move || controller.abort());
        let options = web_sys::RequestInit::new();
        options.set_method("POST");
        options.set_mode(web_sys::RequestMode::Cors);
        options.set_headers(&headers);
        options.set_redirect(web_sys::RequestRedirect::Error);
        options.set_credentials(web_sys::RequestCredentials::Omit);
        options.set_cache(web_sys::RequestCache::NoStore);
        options.set_referrer_policy(web_sys::ReferrerPolicy::NoReferrer);
        options.set_signal(Some(&cancellation.0.signal()));
        options.set_body(&input.to_string().into());
        let call = web_sys::Request::new_with_str_and_init(
            &format!("{}{}", self.base, action.path()),
            &options,
        )
        .map_err(|_| Error::Invalid)?;
        let response = JsFuture::from(window.fetch_with_request(&call))
            .await
            .map_err(|_| Error::Reconcile)?
            .dyn_into::<web_sys::Response>()
            .map_err(|_| Error::Reconcile)?;
        let status = response.status();
        const LIMIT: usize = 16 * 1024 * 1024;
        if response
            .headers()
            .get("content-length")
            .map_err(|_| Error::Reconcile)?
            .is_some_and(|size| size.parse::<u64>().is_ok_and(|size| size > LIMIT as u64))
        {
            return Err(Error::Reconcile);
        }
        let stream = response.body().ok_or(Error::Reconcile)?;
        let reader = stream
            .get_reader()
            .dyn_into::<web_sys::ReadableStreamDefaultReader>()
            .map_err(|_| Error::Reconcile)?;
        let mut bytes = Vec::new();
        loop {
            let next = JsFuture::from(reader.read())
                .await
                .map_err(|_| Error::Reconcile)?;
            let done = js_sys::Reflect::get(&next, &"done".into())
                .map_err(|_| Error::Reconcile)?
                .as_bool()
                .ok_or(Error::Reconcile)?;
            if done {
                break;
            }
            let chunk = js_sys::Reflect::get(&next, &"value".into())
                .map_err(|_| Error::Reconcile)?
                .dyn_into::<js_sys::Uint8Array>()
                .map_err(|_| Error::Reconcile)?;
            if chunk.length() as usize > LIMIT - bytes.len() {
                return Err(Error::Reconcile);
            }
            bytes.extend_from_slice(&chunk.to_vec());
        }
        let result = super::decode_response(name, status, &bytes);
        drop(timeout);
        drop(cancellation);
        result
    }
}

// Abort the browser-owned Fetch and body reader if the future is cancelled or a size/error
// guard exits early. The timer separately bounds the entire response lifetime.
struct CancelOnDrop(web_sys::AbortController);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl Transport for BrowserClient {
    async fn send(&mut self, path: &str, request: Value) -> Result<Value> {
        let name = path.strip_prefix("/v1/").ok_or(Error::Invalid)?;
        self.call(name, request).await
    }
}
