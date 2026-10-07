//! The pinned HTTP client refuses unsafe origins and never trusts oversized replies.
use cvld::{
    client::{HttpClient, action},
    error::Error,
};
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[test]
fn base_urls_must_be_exact_pinned_origins() {
    for base in [
        "not a url",
        "http://user@127.0.0.1:1",
        "http://:secret@127.0.0.1:1",
        "http://127.0.0.1:1/?query=1",
        "http://127.0.0.1:1/#fragment",
        "http://127.0.0.1:1/path",
        "ftp://127.0.0.1:1",
        "http://example.test",
    ] {
        assert!(
            matches!(
                HttpClient::new(base.into(), "host.example.test".into(), None),
                Err(Error::Invalid)
            ),
            "{base}"
        );
    }
    assert!(matches!(
        HttpClient::new(
            "https://other.example.test".into(),
            "host.example.test".into(),
            None
        ),
        Err(Error::WrongHost)
    ));
    for base in [
        "https://host.example.test",
        "http://127.0.0.1:1",
        "http://[::1]:1",
        "http://localhost:1",
    ] {
        assert!(HttpClient::new(base.into(), "host.example.test".into(), None).is_ok());
    }
}

#[test]
fn the_contract_exposes_registered_operations_only() {
    let operation = action("global_public").unwrap();
    assert!(operation.schema().is_object());
    assert_eq!(operation.path(), "/v1/global_public");
    assert!(action("not_registered").is_none());
}

#[tokio::test]
async fn unknown_actions_are_not_dispatched_and_oversized_replies_are_unknown_outcomes() {
    let unreachable = HttpClient::new("http://127.0.0.1:1".into(), "h".into(), None).unwrap();
    assert!(matches!(
        unreachable.call("../not_registered", json!({})).await,
        Err(Error::Invalid)
    ));
    // The peer announces a body far beyond the client limit and then stalls.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let _ = socket.read(&mut request).await;
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 20000000\r\n\r\n",
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    let client = HttpClient::new(base, "h".into(), None).unwrap();
    assert!(matches!(
        client.call("global_public", json!({})).await,
        Err(Error::Reconcile)
    ));
    server.abort();
}
