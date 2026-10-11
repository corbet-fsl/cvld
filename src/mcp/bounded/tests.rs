use super::*;
use rmcp::{
    RoleServer,
    transport::{Transport as _, async_rw::AsyncRwTransport},
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

type Server =
    AsyncRwTransport<RoleServer, BoundedRead<ReadHalf<DuplexStream>>, WriteHalf<DuplexStream>>;
fn transport(limit: usize) -> (DuplexStream, Server) {
    let (peer, server) = tokio::io::duplex(8192);
    let (read, write) = tokio::io::split(server);
    (
        peer,
        AsyncRwTransport::new_server(BoundedRead::new(read, limit), write),
    )
}
fn ping(id: u64) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":"ping"})).unwrap();
    bytes.push(b'\n');
    bytes
}

#[tokio::test]
async fn actual_sdk_accepts_multiple_individually_bounded_frames_in_one_read() {
    let first = ping(1);
    let maximum = first.len();
    let (mut peer, mut server) = transport(maximum);
    let all: Vec<_> = [first, ping(2), ping(3)].concat();
    assert!(all.len() > maximum);
    peer.write_all(&all).await.unwrap();
    for id in 1..=3 {
        let request = server.receive().await.unwrap();
        assert_eq!(serde_json::to_value(request).unwrap()["id"], id);
    }
}

#[tokio::test]
async fn cancelled_sdk_receive_preserves_the_original_partial_frame_and_bound() {
    let frame = ping(1);
    let (mut peer, mut server) = transport(frame.len());
    peer.write_all(&frame[..12]).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), server.receive())
            .await
            .is_err()
    );
    peer.write_all(&frame[12..]).await.unwrap();
    let request = server.receive().await.unwrap();
    assert_eq!(serde_json::to_value(request).unwrap()["id"], 1);
    peer.write_all(&ping(2)).await.unwrap();
    let request = server.receive().await.unwrap();
    assert_eq!(serde_json::to_value(request).unwrap()["id"], 2);
}

#[tokio::test]
async fn oversized_split_frame_never_becomes_an_sdk_request_and_fences_the_stream() {
    let frame = ping(1);
    let (mut peer, mut server) = transport(frame.len() - 1);
    peer.write_all(&frame[..12]).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), server.receive())
            .await
            .is_err()
    );
    peer.write_all(&frame[12..]).await.unwrap();
    // The real SDK receives the adapter's fixed I/O refusal; its parser cannot
    // return this command to a handler. An equal retry never resets the bound.
    assert!(server.receive().await.is_none());
    peer.write_all(&ping(2)).await.unwrap();
    assert!(server.receive().await.is_none());
}

#[tokio::test]
async fn many_split_reads_cannot_bypass_a_frame_limit_without_a_delimiter() {
    let (mut writer, reader) = tokio::io::duplex(64);
    let mut reader = BoundedRead::new(reader, 10);
    let task = tokio::spawn(async move {
        for _ in 0..11 {
            writer.write_all(b"x").await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    let mut bytes = Vec::new();
    assert_eq!(
        reader.read_to_end(&mut bytes).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(bytes.len() <= 10);
    task.await.unwrap();
    let mut buffer = [0; 1];
    assert_eq!(
        reader.read(&mut buffer).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn argument_bounds_count_actual_encoded_bytes_without_a_second_allocation() {
    // Quotation and escaping count exactly as they will on the real HTTP wire.
    let exact = serde_json::Value::String("x".repeat(ORDINARY_ARGUMENT_BYTES - 2));
    assert!(arguments_fit("initial_creation", &exact).is_ok());
    let too_large = serde_json::Value::String("x".repeat(ORDINARY_ARGUMENT_BYTES - 1));
    assert!(arguments_fit("initial_creation", &too_large).is_err());
    assert!(arguments_fit("account", &too_large).is_ok());
    let escaped = serde_json::Value::String("\n".repeat(ORDINARY_ARGUMENT_BYTES / 2));
    assert!(arguments_fit("initial_creation", &escaped).is_err());
    let too_large = serde_json::Value::String("x".repeat(ACCOUNT_ARGUMENT_BYTES - 1));
    assert!(arguments_fit("account", &too_large).is_err());
    let unknown = serde_json::Value::String("x".repeat(ORDINARY_ARGUMENT_BYTES));
    assert!(arguments_fit("unknown_account_override", &unknown).is_err());
}
