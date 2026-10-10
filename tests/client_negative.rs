#![cfg(all(feature = "development-gate", not(target_arch = "wasm32")))]
use cvld::{
    client::{HttpClient, Transport},
    error::Error,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_origins_headers_and_paths_are_refused_before_dispatch() {
    for base in [
        "not a url",
        "https://user@wallet.example.test",
        "https://:secret@wallet.example.test",
        "https://wallet.example.test/?private",
        "https://wallet.example.test/#private",
        "https://wallet.example.test/private",
        "http://wallet.example.test",
        "ftp://localhost/",
    ] {
        assert!(matches!(
            HttpClient::new(base.into(), "wallet.example.test".into(), None),
            Err(Error::Invalid)
        ));
    }
    for base in [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "https://wallet.example.test/",
    ] {
        assert!(HttpClient::new(base.into(), "wallet.example.test".into(), None).is_ok());
    }
    let mut client = HttpClient::new(
        "http://127.0.0.1:1/".into(),
        "invalid\nprivate".into(),
        None,
    )
    .unwrap();
    assert!(matches!(
        client.call("global_public", json!({})).await,
        Err(Error::Invalid)
    ));
    assert!(matches!(
        client.call("unknown", json!({})).await,
        Err(Error::Invalid)
    ));
    assert!(matches!(
        client.send("/unregistered", json!({})).await,
        Err(Error::Invalid)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbounded_chunked_reply_is_stopped_at_the_byte_limit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut buffer = [0; 4096];
            let received = stream.read(&mut buffer).await.unwrap();
            assert!(received > 0);
            request.extend_from_slice(&buffer[..received]);
            if request
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .is_some_and(|end| request.len() >= end + 4 + 2)
            {
                break;
            }
        }
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let bytes = vec![b' '; 8 * 1024 * 1024];
        for _ in 0..2 {
            stream.write_all(b"800000\r\n").await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
        }
        let _ = stream.write_all(b"1\r\nx\r\n0\r\n\r\n").await;
    });
    let client = HttpClient::new(base, "wallet.example.test".into(), None).unwrap();
    assert!(matches!(
        client.call("global_public", json!({})).await,
        Err(Error::Reconcile)
    ));
    server.await.unwrap();
}
