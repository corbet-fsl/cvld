//! Real HTTP services with scheduling barriers around their actual locks.
use super::*;
#[path = "../tests/support/mod.rs"]
mod support;
use serde_json::json;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn pending_body(
    service: &Running,
    host: &str,
    token: &str,
    action: &str,
) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(service.base.trim_start_matches("http://"))
        .await
        .unwrap();
    stream.write_all(format!("POST /v1/{action} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut interim = [0; 25];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut interim))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    stream
}
async fn finish_body(mut stream: tokio::net::TcpStream, status: &str) {
    stream.write_all(b"{}").await.unwrap();
    let mut response = [0; 12];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, format!("HTTP/1.1 {status}").as_bytes());
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_body_cannot_block_logout_or_reuse_its_revoked_session() {
    let service = global(100).await;
    let member = enrol(&service, WALLET, None).await;
    let pending = pending_body(&service, WALLET, &member.session, "passport_challenge").await;
    tokio::time::timeout(Duration::from_secs(3), service.door.maintain())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(3),
            call_status(&service, WALLET, Some(&member.session), "logout", json!({}))
        )
        .await
        .unwrap(),
        200
    );
    finish_body(pending, "401").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn execution_uses_time_after_the_serialization_wait() {
    let service = global(100).await;
    let member = enrol(&service, WALLET, None).await;
    let guard = service.door.inner.requests.lock().await;
    let mut pending = pending_body(&service, WALLET, &member.session, "passport_challenge").await;
    pending.write_all(b"{}").await.unwrap();
    service.clock.set(NOW + 601);
    drop(guard);
    let mut response = [0; 12];
    pending.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"HTTP/1.1 401");
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_body_cannot_use_a_passkey_revoked_while_reading() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("revoke", &public).await;
    let host = "api.revoke.example.test";
    let member = enrol_community(&service, host, &passport).await;
    let pending = pending_body(&service, host, &member.session, "lobby").await;
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(3),
            call_status(
                &service,
                host,
                Some(&member.session),
                "passkey_revoke",
                json!({"credential": member.credential})
            )
        )
        .await
        .unwrap(),
        200
    );
    finish_body(pending, "401").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn public_snapshots_and_watches_do_not_wait_for_private_locks() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community("public", &public).await;
    let _global_guard = global.door.global_backend().unwrap().lock().await;
    let _global_requests = global.door.inner.requests.lock().await;
    let _community_guard = community.door.community_backend().unwrap().lock().await;
    let _community_requests = community.door.inner.requests.lock().await;
    for (service, host, action, body) in [
        (&global, WALLET, "global_public", json!({})),
        (
            &community,
            "api.public.example.test",
            "trust_feed",
            json!({}),
        ),
        (
            &community,
            "api.public.example.test",
            "trust_changes",
            json!({"revision": 0}),
        ),
    ] {
        // Even an irrelevant bearer must not trigger a private database lookup.
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(3),
                call_status(
                    service,
                    host,
                    Some("synthetic-unrecognized-bearer"),
                    action,
                    body
                )
            )
            .await
            .unwrap(),
            200
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn all_registry_actions_are_throttled_before_waiting_on_locks() {
    let service = global(1).await;
    let _guard = service.door.inner.requests.lock().await;
    for action in ACTIONS {
        // A wrong host refuses cheaply even while a private action is running.
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(3),
                call_status(
                    &service,
                    "foreign.example.test",
                    None,
                    action.name,
                    json!({})
                )
            )
            .await
            .unwrap(),
            421
        );
        assert_eq!(
            call_status(&service, WALLET, None, action.name, json!({})).await,
            429
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn in_flight_limits_are_nonwaiting_and_watch_capacity_is_separate() {
    let service = global(1000).await;
    for (name, count) in [
        ("register_begin", 32),
        ("passport_issue", 32),
        ("trust_changes", 16),
    ] {
        let action = action(name).unwrap();
        let mut permits = Vec::new();
        for _ in 0..count {
            permits.push(service.door.admit_request(action).await.unwrap());
        }
        assert!(matches!(
            service.door.admit_request(action).await,
            Err(Error::Throttled)
        ));
        if name == "trust_changes" {
            assert!(
                service
                    .door
                    .admit_request(crate::api::action("global_public").unwrap())
                    .await
                    .is_ok()
            );
        }
        permits.pop();
        assert!(service.door.admit_request(action).await.is_ok());
    }
}
