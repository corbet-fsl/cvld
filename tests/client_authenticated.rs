//! The owner capability uses actual pinned HTTPS, never a caller transport claim.
#![cfg(all(feature = "development-gate", not(target_arch = "wasm32")))]
mod support;
use cvld::{
    client::{Client, HttpClient},
    error::Error,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

struct TlsDoor {
    origin: String,
    address: String,
    root: Vec<u8>,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for TlsDoor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
// Adapt the original CFYR tests/trust.rs maintained TLS bridge. It forwards only
// an actual public Door call without manufacturing domain facts or verdicts.
async fn tls_door(service: &Running) -> TlsDoor {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let root = cert.der().clone();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![root.clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let upstream = client(service, WALLET, None);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(config));
        loop {
            let (io, _) = listener.accept().await.unwrap();
            let Ok(mut tls) = acceptor.accept(io).await else {
                continue;
            };
            let mut bytes = Vec::new();
            let request = loop {
                let mut chunk = [0; 4096];
                let Ok(count) = tls.read(&mut chunk).await else {
                    break None;
                };
                if count == 0 {
                    break None;
                }
                assert!(bytes.len() + count <= 8192);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let length: usize = header
                        .lines()
                        .find_map(|v| v.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        assert_eq!(
                            header.lines().next().unwrap(),
                            "post /v1/global_public http/1.1"
                        );
                        assert_eq!(
                            serde_json::from_slice::<serde_json::Value>(
                                &bytes[end + 4..end + 4 + length]
                            )
                            .unwrap(),
                            json!({})
                        );
                        break Some(());
                    }
                }
            };
            if request.is_none() {
                continue;
            }
            observed.fetch_add(1, Ordering::SeqCst);
            let value = upstream.call("global_public", json!({})).await.unwrap();
            let body = serde_json::to_vec(&value).unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tls.write_all(header.as_bytes()).await.unwrap();
            tls.write_all(&body).await.unwrap();
            tls.shutdown().await.unwrap();
        }
    });
    TlsDoor {
        origin,
        address,
        root: root.to_vec(),
        calls,
        task,
    }
}

#[test]
fn only_the_actual_canonical_https_origin_qualifies_and_http_fixture_overrides_do_not() {
    let pinned = Client::new(
        HttpClient::new(
            "https://wallet.example.test:443/".into(),
            WALLET.into(),
            None,
        )
        .unwrap(),
    );
    assert_eq!(
        pinned.authenticated_origin().unwrap(),
        "https://wallet.example.test"
    );
    for base in ["http://localhost/", "http://127.0.0.1/", "http://[::1]/"] {
        // The original native fixture host override is still usable for generic
        // calls, but can never supply authenticated live-server observations.
        let caller = Client::new(HttpClient::new(base.into(), WALLET.into(), None).unwrap());
        assert!(matches!(
            caller.authenticated_origin(),
            Err(Error::WrongHost)
        ));
    }
    assert!(matches!(
        HttpClient::new(
            "https://wallet.example.test/".into(),
            "other.example.test".into(),
            None
        ),
        Err(Error::WrongHost)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_tls_door_requires_its_root_and_exact_hostname_before_any_http_observation() {
    let service = global(100).await;
    let tls = tls_door(&service).await;
    let mut untrusted =
        Client::new(HttpClient::new(tls.origin.clone(), "localhost".into(), None).unwrap());
    // Configuration alone is inert; untrusted TLS cannot yield a live result.
    assert_eq!(untrusted.authenticated_origin().unwrap(), tls.origin);
    assert!(matches!(
        untrusted.call("global_public", json!({})).await,
        Err(Error::Reconcile)
    ));
    let mut wrong_hostname = Client::new(
        HttpClient::with_roots(
            format!("https://{}", tls.address),
            "127.0.0.1".into(),
            None,
            std::slice::from_ref(&tls.root),
        )
        .unwrap(),
    );
    assert!(matches!(
        wrong_hostname.call("global_public", json!({})).await,
        Err(Error::Reconcile)
    ));
    assert_eq!(tls.calls.load(Ordering::SeqCst), 0);
    let mut pinned = Client::new(
        HttpClient::with_roots(
            tls.origin.clone(),
            "localhost".into(),
            None,
            std::slice::from_ref(&tls.root),
        )
        .unwrap(),
    );
    assert_eq!(pinned.authenticated_origin().unwrap(), tls.origin);
    let value = pinned.call("global_public", json!({})).await.unwrap();
    assert!(value["issuer"].is_array());
    assert_eq!(tls.calls.load(Ordering::SeqCst), 1);
    assert_eq!(pinned.authenticated_origin().unwrap(), tls.origin);
}
