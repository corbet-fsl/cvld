//! Production-mode HTTP lifecycle uses only real stored UV passkey ownership.
#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
mod support;
use cvld::{api::*, service::Door};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::AtomicU64};
use support::{
    resident::{Resident, strip_prf},
    *,
};

async fn production() -> Running {
    let dir = tempfile::tempdir().unwrap();
    let mut config = global_config(dir.path(), 200).await;
    // Production mode requires an actual production issuer catalogue and
    // matching signed policy. No gate or provider is executed in this journey.
    let issuer = cpsd::IssuerKey::generate(
        &mut cpsd::rand::rngs::OsRng,
        cpsd::KeyId::new("production-enrollment-fixture").unwrap(),
        vec![cpsd::GateId::new("cphn").unwrap()],
    )
    .unwrap();
    std::fs::write(&config.issuer_key_file, issuer.to_secret_bytes()).unwrap();
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "policy-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        NOW - 1,
        86_400 * 100,
    )
    .await
    .unwrap();
    let policy = cgbl::Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: (NOW / 86_400 + 40) * 86_400,
        gates: vec![cgbl::GatePolicy {
            gate: "cphn".into(),
            provider: "twilio".into(),
            uniqueness: true,
        }],
    };
    let signed = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            NOW,
            policy.shared_expiry + 1,
        )
        .await
        .unwrap();
    std::fs::write(&config.policy_file, signed).unwrap();
    config.development = false;
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let door = Door::global(config, clock.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Running {
        base,
        door,
        clock,
        task,
        dir,
    }
}
async fn signed_response(device: &mut Resident, options: Value, create: bool) -> Value {
    let mut credential = device
        .ceremony(options, create, &format!("https://vault.{WALLET}"))
        .await;
    strip_prf(&mut credential);
    credential
}
async fn login(service: &Running, device: &mut Resident) -> Session {
    let api = client(service, WALLET, None);
    let begin: DiscoverableCeremony = serde_json::from_value(
        api.call("login_discoverable_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let credential = signed_response(device, begin.options, false).await;
    serde_json::from_value(
        api.call(
            "login_finish",
            json!({"ceremony":begin.ceremony,"credential":credential}),
        )
        .await
        .unwrap(),
    )
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_wallet_uuid_seed_uv_query_bind_and_permanent_block_are_joined() {
    let service = production().await;
    let api = client(&service, WALLET, None);
    let original: Ceremony =
        serde_json::from_value(api.call("register_begin", json!({})).await.unwrap()).unwrap();
    let body = json!({"ceremony":original.ceremony,"seed":vec![1u8;32]});
    let first: InitialCeremony = serde_json::from_value(
        api.call("global_initial_registration_continue", body.clone())
            .await
            .unwrap(),
    )
    .unwrap();
    let equal: InitialCeremony = serde_json::from_value(
        api.call("global_initial_registration_continue", body.clone())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first.user, original.user);
    assert_eq!(first.ceremony, original.ceremony);
    assert_eq!(first.options, equal.options);
    assert_eq!(first.expires_at, NOW + 300);
    assert_eq!(first.checked_at, NOW);
    assert_eq!(
        call_status(
            &service,
            WALLET,
            None,
            "global_initial_registration_continue",
            json!({"ceremony":original.ceremony,"seed":vec![2u8;32]})
        )
        .await,
        409
    );
    assert_eq!(
        call_status(
            &service,
            ROOT,
            None,
            "global_initial_registration_continue",
            body.clone()
        )
        .await,
        403
    );
    assert_eq!(
        call_status(
            &service,
            WALLET,
            None,
            "global_initial_registration_continue",
            json!({"ceremony":original.ceremony,"seed":vec![1u8;32],"user":original.user})
        )
        .await,
        400
    );
    let mut device = Resident::default();
    let credential = signed_response(&mut device, first.options, true).await;
    api.call(
        "register_finish",
        json!({"ceremony":first.ceremony,"credential":credential}),
    )
    .await
    .unwrap();
    assert_eq!(
        call_status(
            &service,
            WALLET,
            None,
            "global_initial_registration_continue",
            body
        )
        .await,
        401
    );
    let session = login(&service, &mut device).await;
    let api = client(&service, WALLET, Some(&session.token));
    let before: InitialCreationResponse =
        serde_json::from_value(api.call("initial_creation", json!({})).await.unwrap()).unwrap();
    assert_eq!(before.seed, [1; 32]);
    assert_eq!(before.publication, None);
    let bind = json!({"seed":vec![1u8;32],"publication":vec![2u8;32]});
    for _ in 0..2 {
        let state: InitialCreationResponse = serde_json::from_value(
            api.call("initial_publication_bind", bind.clone())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(state.publication, Some([2; 32]));
    }
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&session.token),
            "initial_publication_bind",
            json!({"seed":vec![1u8;32],"publication":vec![3u8;32]})
        )
        .await,
        409
    );
    let pending: SelfBanChallenge =
        serde_json::from_value(api.call("global_self_ban_begin", json!({})).await.unwrap())
            .unwrap();
    let credential = signed_response(&mut device, pending.options, false).await;
    api.call(
        "global_self_ban_finish",
        json!({"ceremony":pending.ceremony,"credential":credential}),
    )
    .await
    .unwrap();
    let fresh = login(&service, &mut device).await;
    let api = client(&service, WALLET, Some(&fresh.token));
    // Query is own metadata only; a terminal ban grants no renewed admission.
    let state: InitialCreationResponse =
        serde_json::from_value(api.call("initial_creation", json!({})).await.unwrap()).unwrap();
    assert_eq!(state.publication, Some([2; 32]));
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&fresh.token),
            "initial_publication_bind",
            bind
        )
        .await,
        409
    );
    assert!(
        serde_json::from_value::<SelfBanStatus>(
            api.call("global_self_ban_status", json!({})).await.unwrap()
        )
        .unwrap()
        .self_banned
    );
}
