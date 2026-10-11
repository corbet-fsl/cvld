//! Actual TLS/framing tests, using public bytes from a real Door.
//! The bytes are NOT a record fixture and fetching them grants no authority.
#![cfg(all(feature = "development-gate", not(target_arch = "wasm32")))]
mod support;
use cvld::{
    client::{Client, HttpClient},
    error::Error,
};
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

#[derive(Clone, Copy)]
enum Frame {
    Fixed,
    Chunked,
    Close,
    Under,
    Over,
    HeaderMismatch,
    Redirect,
    Hold,
}
struct Peer {
    origin: String,
    root: Vec<u8>,
    calls: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
    ready: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Peer {
    fn client(&self) -> Client<HttpClient> {
        Client::new(
            HttpClient::with_roots(
                self.origin.clone(),
                "localhost".into(),
                Some("fictional-bearer-must-not-be-sent".into()),
                std::slice::from_ref(&self.root),
            )
            .unwrap(),
        )
    }
}
// Reuse the maintained rcgen/Tokio TLS bridge from client_authenticated.rs.
// Only transport framing is varied; no proof/provider/authority is fabricated.
async fn peer(body: Vec<u8>, frame: Frame) -> Peer {
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
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let closed = Arc::new(AtomicBool::new(false));
    let closure = closed.clone();
    let ready = Arc::new(tokio::sync::Notify::new());
    let started = ready.clone();
    let task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(config));
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let Ok(mut tls) = acceptor.accept(socket).await else {
                continue;
            };
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let count = tls.read(&mut chunk).await.unwrap();
                if count == 0 {
                    break;
                }
                assert!(request.len() + count <= 8192);
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|v| v == b"\r\n\r\n") {
                    break;
                }
            }
            let header = String::from_utf8_lossy(&request).to_ascii_lowercase();
            observed.fetch_add(1, Ordering::SeqCst);
            assert!(header.starts_with("get /v1/account_record_object http/1.1\r\n"));
            assert!(!header.contains("authorization:"));
            let framing = match frame {
                Frame::Fixed | Frame::Hold => format!("Content-Length: {}\r\n", body.len()),
                Frame::HeaderMismatch => format!("Content-Length: {}\r\n", body.len() + 1),
                Frame::Chunked => "Transfer-Encoding: chunked\r\n".into(),
                Frame::Redirect => {
                    "Location: /must-not-be-followed\r\nContent-Length: 0\r\n".into()
                }
                _ => String::new(),
            };
            let status = if matches!(frame, Frame::Redirect) {
                "302 Found"
            } else {
                "200 OK"
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\n{framing}Connection: close\r\n\r\n"
            );
            if tls.write_all(response.as_bytes()).await.is_err() {
                continue;
            }
            if matches!(frame, Frame::Hold) {
                started.notify_one();
                let mut remaining = [0; 1];
                if !matches!(tls.read(&mut remaining).await, Ok(1)) {
                    closure.store(true, Ordering::SeqCst);
                }
                continue;
            }
            match frame {
                Frame::Chunked => {
                    for part in body.chunks(7) {
                        if tls
                            .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                        if tls.write_all(part).await.is_err() {
                            break;
                        }
                        if tls.write_all(b"\r\n").await.is_err() {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    let _ = tls.write_all(b"0\r\n\r\n").await;
                }
                Frame::Under => {
                    let _ = tls.write_all(&body[..body.len() - 1]).await;
                }
                Frame::Over => {
                    let _ = tls.write_all(&body).await;
                    let _ = tls.write_all(&[0]).await;
                }
                Frame::Redirect => {}
                _ => {
                    let _ = tls.write_all(&body).await;
                }
            }
            let _ = tls.shutdown().await;
        }
    });
    Peer {
        origin,
        root: root.to_vec(),
        calls,
        closed,
        ready,
        task,
    }
}
async fn public_bytes() -> Vec<u8> {
    let service = global(100).await;
    let value = client(&service, WALLET, None)
        .call("global_public", json!({}))
        .await
        .unwrap();
    serde_json::to_vec(&value).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_fixed_chunked_and_close_framing_return_the_same_public_bytes_without_bearer() {
    let bytes = public_bytes().await;
    for frame in [Frame::Fixed, Frame::Chunked, Frame::Close] {
        let peer = peer(bytes.clone(), frame).await;
        assert_eq!(
            peer.client()
                .account_record_object(bytes.len())
                .await
                .unwrap(),
            bytes
        );
        assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_over_header_mismatch_and_redirect_refuse_without_retry() {
    let bytes = public_bytes().await;
    for frame in [
        Frame::Under,
        Frame::Over,
        Frame::HeaderMismatch,
        Frame::Redirect,
    ] {
        let peer = peer(bytes.clone(), frame).await;
        assert!(matches!(
            peer.client().account_record_object(bytes.len()).await,
            Err(Error::Reconcile)
        ));
        assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_the_owned_body_read_closes_the_actual_tls_stream() {
    let bytes = public_bytes().await;
    let peer = peer(bytes.clone(), Frame::Hold).await;
    let mut client = peer.client();
    let mut fetch = Box::pin(client.account_record_object(bytes.len()));
    tokio::select! {
        value = &mut fetch => panic!("held stream completed prematurely: {value:?}"),
        _ = peer.ready.notified() => {},
    }
    // The underlying future, not merely its pinned reference, must be dropped.
    drop(fetch);
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !peer.closed.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_whole_request_timeout_bounds_a_real_stalled_tls_body() {
    let bytes = public_bytes().await;
    let peer = peer(bytes.clone(), Frame::Hold).await;
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(35),
        peer.client().account_record_object(bytes.len()),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(Error::Reconcile)));
    assert!(started.elapsed() >= Duration::from_secs(29));
    assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
}
