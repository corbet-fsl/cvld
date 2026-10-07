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

#[tokio::test(flavor = "multi_thread")]
async fn a_passkey_revoked_underneath_a_live_global_session_ends_it() {
    let service = global(100).await;
    let member = enrol(&service, WALLET, None).await;
    let passkeys = service
        .door
        .auth(WALLET)
        .unwrap()
        .lock()
        .await
        .passkeys
        .clone();
    let user = ckyh::Uuid::parse_str(&member.user).unwrap();
    let credential = ckyh::CredentialID::from(member.credential.clone());
    tokio::task::spawn_blocking(move || passkeys.revoke(user, &credential))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "passport_challenge",
            json!({})
        )
        .await,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_passkey_revoked_underneath_a_live_community_session_ends_it() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("underneath", &public).await;
    let host = "api.underneath.example.test";
    let member = enrol_community(&service, host, &passport).await;
    {
        let mut backend = service.door.community_backend().unwrap().lock().await;
        let (grant, authentication) = backend.authenticate(&member.session, NOW).await.unwrap();
        backend
            .facade
            .membership()
            .revoke_passkey(&authentication, grant.credential.clone())
            .await
            .unwrap();
        // Logging out a session that no longer exists changes nothing.
        backend.logout("synthetic-unknown-session");
    }
    assert_eq!(
        call_status(&service, host, Some(&member.session), "lobby", json!({})).await,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn each_door_refuses_the_other_scope_without_touching_its_backend() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let scoped = community("scoped", &public).await;
    assert!(matches!(
        global.door.community_backend(),
        Err(Error::WrongHost)
    ));
    assert!(matches!(
        global.door.community_public(),
        Err(Error::WrongHost)
    ));
    assert!(matches!(
        scoped.door.global_backend(),
        Err(Error::WrongHost)
    ));
    let context = Context {
        host: WALLET.into(),
        grant: None,
        token: None,
        now: NOW,
        authentication: None,
    };
    assert!(matches!(
        scoped.door.global_public(context, Empty {}).await,
        Err(Error::WrongHost)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_need_usable_limits_and_operators_need_a_long_capability() {
    let dir = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", dir.path().join("auth.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&[crlt::Migration::new(1, "passkeys", ckyh::LIBSQL_SCHEMA)])
        .await
        .unwrap();
    let passkeys = || {
        ckyh::Passkeys::new(
            ckyh::LibsqlStore::new(&db, "limits", tokio::runtime::Handle::current()).unwrap(),
            "limits",
            "auth.example.test",
            &[ckyh::Url::parse("https://auth.example.test").unwrap()],
        )
        .unwrap()
    };
    let capability = |text: &str| Some(zeroize::Zeroizing::new(text.to_owned()));
    for (capacity, lifetime, bootstrap) in [
        (0, 600, None),
        (1, 0, None),
        (1, 3_601, None),
        (1, 600, capability("short")),
    ] {
        assert!(matches!(
            Auth::new(
                passkeys(),
                Role::Member,
                None,
                bootstrap,
                capacity,
                lifetime
            ),
            Err(Error::Invalid)
        ));
    }
    assert!(
        Auth::new(
            passkeys(),
            Role::Root,
            Some(ckyh::Uuid::nil()),
            capability("c".repeat(32).as_str()),
            1,
            600
        )
        .is_ok()
    );
}

#[tokio::test]
async fn the_unconfigured_authority_denies_every_order_and_unrepresentable_time_is_denied() {
    use clbs::Verifier;
    let order = || clbs::SignedOrder {
        order: clbs::Order {
            community: "synthetic".into(),
            id: "order".into(),
            subject: "subject".into(),
            reference: "reference".into(),
            entered_by: "operator".into(),
            kind: clbs::OrderKind::SelfBan,
            scope: clbs::Scope::All,
            period: clbs::Period {
                starts_at: 0,
                ends_at: None,
            },
        },
        proof: Vec::new(),
    };
    let authority = crate::community::UnconfiguredAuthority;
    assert!(matches!(
        authority.verify_legal(&order()).await,
        Err(clbs::Error::Denied)
    ));
    assert!(matches!(
        authority.verify_self_ban(&order()).await,
        Err(clbs::Error::Denied)
    ));
    let overflow = crate::community::CommunityClock(Arc::new(TestClock(
        std::sync::atomic::AtomicU64::new(u64::MAX),
    )));
    assert!(matches!(
        clbs::Clock::now(&overflow),
        Err(clbs::Error::Denied)
    ));
    let current = crate::community::CommunityClock(Arc::new(TestClock(
        std::sync::atomic::AtomicU64::new(NOW),
    )));
    assert_eq!(clbs::Clock::now(&current).unwrap(), NOW as i64);
}
