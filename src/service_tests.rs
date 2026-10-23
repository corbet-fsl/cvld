//! Real HTTP services with scheduling barriers around their actual locks.
use super::*;
use crate::test_support as support;
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
    let mut member = enrol_community(&service, host, &passport).await;
    let pending = pending_body(&service, host, &member.session, "lobby").await;
    let proof = support::step_up(
        &service,
        host,
        &member.session,
        &mut member.authenticator,
        json!({"kind":"passkey_revoke","credential":member.credential}),
    )
    .await;
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(3),
            call_status(
                &service,
                host,
                Some(&member.session),
                "passkey_revoke",
                json!({"credential": member.credential,"step_up":proof})
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
        ("register_begin", 16),
        ("passport_issue", 32),
        ("trust_changes", 16),
    ] {
        let action = action(name).unwrap();
        let mut permits = Vec::new();
        for _ in 0..count {
            permits.push(service.door.admit_request(action, SOURCE).await.unwrap());
        }
        assert!(matches!(
            service.door.admit_request(action, SOURCE).await,
            Err(Error::Throttled)
        ));
        if name == "trust_changes" {
            assert!(
                service
                    .door
                    .admit_request(crate::api::action("global_public").unwrap(), SOURCE)
                    .await
                    .is_ok()
            );
        }
        permits.pop();
        assert!(service.door.admit_request(action, SOURCE).await.is_ok());
    }
}

async fn request_from(service: &Running, peer: &str, forwarded: Option<&str>, action: &str) -> u16 {
    use tower::ServiceExt as _;
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/{action}"))
        .header("host", WALLET)
        .header("content-type", "application/json");
    if let Some(client) = forwarded {
        builder = builder.header("cf-connecting-ip", client);
    }
    let mut request = builder.body(axum::body::Body::from("{}")).unwrap();
    request.extensions_mut().insert(axum::extract::ConnectInfo(
        peer.parse::<std::net::SocketAddr>().unwrap(),
    ));
    crate::api::router(service.door.clone())
        .oneshot(request)
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread")]
async fn one_source_exhausts_only_its_own_bucket() {
    let service = global(2).await;
    for _ in 0..2 {
        assert_eq!(
            request_from(&service, "198.51.100.7:4000", None, "global_public").await,
            200
        );
    }
    assert_eq!(
        request_from(&service, "198.51.100.7:4001", None, "global_public").await,
        429
    );
    // Another source, another IPv6 /64 and an authenticated-pool action are untouched.
    assert_eq!(
        request_from(&service, "198.51.100.8:4000", None, "global_public").await,
        200
    );
    assert_eq!(
        request_from(&service, "[2001:db8:1:1::1]:4000", None, "global_public").await,
        200
    );
    assert_eq!(
        request_from(&service, "[2001:db8:1:1::2]:4000", None, "global_public").await,
        200
    );
    assert_eq!(
        request_from(&service, "[2001:db8:1:1::3]:4000", None, "global_public").await,
        429
    );
    assert_eq!(
        request_from(&service, "[2001:db8:1:2::1]:4000", None, "global_public").await,
        200
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tunnel_header_names_the_source_only_for_a_loopback_peer() {
    let service = global(1).await;
    assert_eq!(
        request_from(
            &service,
            "127.0.0.1:9",
            Some("203.0.113.5"),
            "global_public"
        )
        .await,
        200
    );
    assert_eq!(
        request_from(
            &service,
            "127.0.0.1:9",
            Some("203.0.113.5"),
            "global_public"
        )
        .await,
        429
    );
    assert_eq!(
        request_from(
            &service,
            "127.0.0.1:9",
            Some("203.0.113.6"),
            "global_public"
        )
        .await,
        200
    );
    // A remote peer cannot choose its bucket with the header.
    assert_eq!(
        request_from(
            &service,
            "198.51.100.9:9",
            Some("203.0.113.7"),
            "global_public"
        )
        .await,
        200
    );
    assert_eq!(
        request_from(
            &service,
            "198.51.100.9:9",
            Some("203.0.113.8"),
            "global_public"
        )
        .await,
        429
    );
}

const SOURCE: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

#[tokio::test(flavor = "multi_thread")]
async fn session_fork_serves_the_wallet_only_and_logout_of_a_sibling_ends_the_family() {
    let service = global(100).await;
    let member = enrol(&service, WALLET, None).await;
    let sibling = client(&service, WALLET, Some(&member.session))
        .call("session_fork", json!({}))
        .await
        .unwrap();
    let token = sibling["token"].as_str().unwrap().to_owned();
    assert_ne!(token, member.session);
    // The sibling is authenticated exactly as its parent: whatever the action answers the
    // parent, it answers the sibling, and never 401.
    let parent = call_status(
        &service,
        WALLET,
        Some(&member.session),
        "wallet_device_keys",
        json!({}),
    )
    .await;
    assert_ne!(parent, 401);
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&token),
            "wallet_device_keys",
            json!({})
        )
        .await,
        parent
    );
    assert_eq!(
        call_status(&service, WALLET, None, "session_fork", json!({})).await,
        401
    );
    assert_eq!(
        call_status(&service, WALLET, Some(&token), "logout", json!({})).await,
        200
    );
    for session in [&token, &member.session] {
        assert_eq!(
            call_status(
                &service,
                WALLET,
                Some(session),
                "wallet_device_keys",
                json!({})
            )
            .await,
            401
        );
        assert_eq!(
            call_status(&service, WALLET, Some(session), "session_fork", json!({})).await,
            401
        );
    }
}

/// The trusted `wallet_register_finish` (the only finish that mints the birth session) serves
/// the wallet's member host only: every community host and the global door's root host refuse
/// it as the wrong host before any ceremony state is read, and the forwarding catalog never
/// offers it, while the forwarded `register_finish` describes no session.
#[tokio::test(flavor = "multi_thread")]
async fn wallet_register_finish_serves_the_wallet_host_only_and_is_never_forwarded() {
    use webauthn_authenticator_rs::{AuthenticatorBackend as _, softtoken::SoftToken};
    let trusted = crate::client::action("wallet_register_finish").unwrap();
    assert_eq!(trusted.schema()["x-client-access"], "trusted");
    assert_eq!(trusted.schema()["x-scope"], "global");
    assert!(crate::client::forwarding_action("wallet_register_finish").is_none());
    let forwarded = crate::client::forwarding_action("register_finish").unwrap();
    let schema = serde_json::to_string(forwarded.schema()).unwrap();
    assert!(!schema.contains("Registered") && !schema.contains("Session"));

    let service = global(100).await;
    let wallet = client(&service, WALLET, None);
    let start: crate::api::Ceremony = serde_json::from_value(
        wallet
            .call("register_begin", json!({"bootstrap":null,"passport":null}))
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge: ckyh::CreationChallengeResponse =
        serde_json::from_value(start.options).unwrap();
    let mut authenticator = SoftToken::new(true).unwrap().0;
    let credential = authenticator
        .perform_register(
            ckyh::Url::parse(&origin_for(WALLET)).unwrap(),
            {
                let mut options = challenge.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();
    let body = json!({"ceremony":start.ceremony,"credential":credential});
    assert_eq!(
        call_status(&service, ROOT, None, "wallet_register_finish", body.clone()).await,
        421
    );
    let public: GlobalPublic =
        serde_json::from_value(wallet.call("global_public", json!({})).await.unwrap()).unwrap();
    let alpha = community("alpha", &public).await;
    for host in ["api.alpha.example.test", "api.admin.alpha.example.test", WALLET] {
        assert_eq!(
            call_status(&alpha, host, None, "wallet_register_finish", body.clone()).await,
            421
        );
    }
    // The refusals consumed nothing: the same ceremony finishes on the wallet host and holds
    // the birth session.
    let registered: crate::api::Registered = serde_json::from_value(
        wallet
            .call("wallet_register_finish", body)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(registered.session.is_some());
}
