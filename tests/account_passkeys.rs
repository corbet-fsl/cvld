//! Actual HTTP management for wallet and operator roles using UV resident keys.
#![cfg(feature = "development-gate")]
mod support;
use cvld::api::*;
use serde_json::{Value, json};
use support::{
    resident::{Resident, strip_prf},
    *,
};

async fn discover(service: &Running, host: &str, device: &mut Resident) -> Session {
    let api = client(service, host, None);
    let begin: DiscoverableCeremony = serde_json::from_value(
        api.call("login_discoverable_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut response = device
        .ceremony(begin.options, false, &support::origin_for(host))
        .await;
    strip_prf(&mut response);
    serde_json::from_value(
        api.call(
            "login_finish",
            json!({"ceremony":begin.ceremony,"credential":response}),
        )
        .await
        .unwrap(),
    )
    .unwrap()
}

async fn register_account(
    service: &Running,
    host: &str,
    body: serde_json::Value,
) -> (Resident, User, Vec<u8>) {
    let public = client(service, host, None);
    let begin: Ceremony =
        serde_json::from_value(public.call("register_begin", body).await.unwrap()).unwrap();
    let mut original = Resident::default();
    let mut response = original
        .ceremony(begin.options, true, &support::origin_for(host))
        .await;
    strip_prf(&mut response);
    let credential: ckyh::RegisterPublicKeyCredential =
        serde_json::from_value(response.clone()).unwrap();
    let original_id = credential.raw_id.as_ref().to_vec();
    let user: User = serde_json::from_value(
        public
            .call(
                "register_finish",
                json!({"ceremony":begin.ceremony,"credential":response}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    (original, user, original_id)
}

async fn scenario(
    service: &Running,
    host: &str,
    other_host: &str,
    role: Role,
    bootstrap: Option<&str>,
) {
    let (original, user, original_id) =
        register_account(service, host, json!({"bootstrap":bootstrap})).await;
    manage(service, host, other_host, role, original, user, original_id).await;
}

async fn manage(
    service: &Running,
    host: &str,
    other_host: &str,
    role: Role,
    mut original: Resident,
    user: User,
    original_id: Vec<u8>,
) {
    let first = discover(service, host, &mut original).await;
    assert_eq!(first.role, role);
    assert_eq!(first.user, user.user);
    let api = client(service, host, Some(&first.token));
    let before: PasskeyList =
        serde_json::from_value(api.call("passkey_list", json!({})).await.unwrap()).unwrap();
    assert_eq!(before.passkeys.len(), 1);
    assert_eq!(before.passkeys[0].credential, original_id);
    assert!(before.passkeys[0].current);
    for (action, body) in [
        ("passkey_list", json!({})),
        ("passkey_add", json!({"step":"begin"})),
        ("passkey_revoke", json!({"credential":original_id})),
    ] {
        assert_eq!(
            call_status(service, host, None, action, body.clone()).await,
            401
        );
        assert_eq!(
            call_status(service, other_host, Some(&first.token), action, body).await,
            401
        );
    }
    // Root's portal sign-in is its step-up; every other role proves a fresh assertion.
    let proof = if role == Role::Root {
        Value::Null
    } else {
        original
            .step_up(service, host, &first.token, json!({"kind":"passkey_add"}))
            .await
    };
    let begin: AddedPasskey = serde_json::from_value(
        api.call("passkey_add", json!({"step":"begin","step_up":proof}))
            .await
            .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Challenge {
        ceremony,
        user: expected,
        options,
    } = begin
    else {
        panic!("challenge")
    };
    assert_eq!(expected, user.user);
    let mut added = Resident::default();
    let mut response = added
        .ceremony(options, true, &support::origin_for(host))
        .await;
    strip_prf(&mut response);
    let body = json!({"step":"finish","ceremony":ceremony,"credential":response});
    assert_eq!(
        call_status(
            service,
            other_host,
            Some(&first.token),
            "passkey_add",
            body.clone()
        )
        .await,
        401
    );
    let registered: AddedPasskey =
        serde_json::from_value(api.call("passkey_add", body.clone()).await.unwrap()).unwrap();
    let AddedPasskey::Registered {
        user: account,
        credential: added_id,
    } = registered
    else {
        panic!("registered")
    };
    assert_eq!(account, user.user);
    assert_eq!(
        call_status(service, host, Some(&first.token), "passkey_add", body).await,
        401
    );
    let second = discover(service, host, &mut added).await;
    assert_eq!(second.user, first.user);
    assert_eq!(second.role, role);
    let second_api = client(service, host, Some(&second.token));
    let proof = if role == Role::Root {
        Value::Null
    } else {
        added
            .step_up(
                service,
                host,
                &second.token,
                json!({"kind":"passkey_revoke","credential":original_id}),
            )
            .await
    };
    second_api
        .call(
            "passkey_revoke",
            json!({"credential":original_id,"step_up":proof}),
        )
        .await
        .unwrap();
    assert_eq!(
        call_status(service, host, Some(&first.token), "passkey_list", json!({})).await,
        401
    );
    let after: PasskeyList =
        serde_json::from_value(second_api.call("passkey_list", json!({})).await.unwrap()).unwrap();
    assert_eq!(after.passkeys.len(), 2);
    let original = after
        .passkeys
        .iter()
        .find(|key| key.credential == original_id)
        .unwrap();
    assert!(original.revoked);
    assert!(!original.current);
    let current = after
        .passkeys
        .iter()
        .find(|key| key.credential == added_id)
        .unwrap();
    assert!(!current.revoked);
    assert!(current.current);
    let proof = if role == Role::Root {
        Value::Null
    } else {
        added
            .step_up(
                service,
                host,
                &second.token,
                json!({"kind":"passkey_revoke","credential":added_id}),
            )
            .await
    };
    let revoked = second_api
        .call(
            "passkey_revoke",
            json!({"credential":added_id,"step_up":proof}),
        )
        .await;
    // Revoking the session's own key ends that session and still answers it
    // with success, on the wallet host exactly as on every other host.
    revoked.unwrap();
    assert_eq!(
        call_status(
            service,
            host,
            Some(&second.token),
            "passkey_list",
            json!({})
        )
        .await,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_wallet_refuses_consumed_addition_before_publication_effects() {
    use cgbl::storage::{Key, Store};
    let service = configured_wallet(100).await;
    let (mut original, _, _) =
        register_account(&service, WALLET, json!({"bootstrap":null,"passport":null})).await;
    let first = discover(&service, WALLET, &mut original).await;
    let api = client(&service, WALLET, Some(&first.token));
    let proof = original
        .step_up(
            &service,
            WALLET,
            &first.token,
            json!({"kind":"passkey_add"}),
        )
        .await;
    let begin: AddedPasskey = serde_json::from_value(
        api.call("passkey_add", json!({"step":"begin","step_up":proof}))
            .await
            .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Challenge {
        ceremony, options, ..
    } = begin
    else {
        panic!("challenge")
    };
    let mut added = Resident::default();
    let mut credential = added
        .ceremony(options, true, &format!("https://vault.{WALLET}"))
        .await;
    strip_prf(&mut credential);
    let body = json!({"step":"finish", "ceremony":ceremony, "credential":credential});
    api.call("passkey_add", body.clone()).await.unwrap();
    let public = client(&service, WALLET, None);
    let feed = public.call("wallet_trust_feed", json!({})).await.unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", service.dir.path().join("global.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&cvld::service::global_migrations())
        .await
        .unwrap();
    let store = cgbl::storage::LibsqlStore::new(&db, "global").unwrap();
    let keys = [
        Key::new("wallet", "publications"),
        Key::new("wallet-device", &first.user),
    ];
    let before = store.read(&keys).await.unwrap();
    assert_eq!(
        call_status(&service, WALLET, Some(&first.token), "passkey_add", body).await,
        401
    );
    let after = store.read(&keys).await.unwrap();
    assert_eq!(after.revisions, before.revisions);
    for key in &keys {
        assert_eq!(after.records[key].value, before.records[key].value);
        assert_eq!(after.records[key].deadline, before.records[key].deadline);
    }
    assert_eq!(
        public.call("wallet_trust_feed", json!({})).await.unwrap(),
        feed
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_and_global_operator_manage_equal_passkeys_through_real_http_routes() {
    let service = global(100).await;
    scenario(&service, WALLET, ROOT, Role::Member, None).await;
    scenario(
        &service,
        ROOT,
        WALLET,
        Role::Root,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn community_root_and_admin_manage_equal_passkeys_on_their_own_hosts() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    scenario(
        &service,
        ROOT,
        "api.admin.alpha.example.test",
        Role::Root,
        Some("synthetic-root-enrolment-capability"),
    )
    .await;
    let member_host = "api.alpha.example.test";
    let proof = presentation(&service, member_host, None, &passport).await;
    let (mut device, user, credential) =
        register_account(&service, member_host, json!({"passport":proof})).await;
    let member = discover(&service, member_host, &mut device).await;
    let subject = passport
        .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
        .to_hex();
    let member_api = client(&service, member_host, Some(&member.token));
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[13; 32])
        .verifying_key()
        .to_bytes();
    member_api
        .call(
            "device_authorize",
            json!({"key":signing_key,"step_up":device.step_up(&service, member_host, &member.token, json!({"kind":"device_authorize","key":signing_key})).await}),
        )
        .await
        .unwrap();
    member_api
        .call("handle_reserve", json!({"handle":"passkey_admin"}))
        .await
        .unwrap();
    member_api
        .call(
            "gate_voucher",
            voucher("alpha", &subject, "passkey-admin", NOW + 172_800),
        )
        .await
        .unwrap();
    let proof = presentation(&service, member_host, Some(&member.token), &passport).await;
    let issued: CredentialResponse = serde_json::from_value(
        member_api
            .call(
                "credential_issue",
                json!({"presentation":proof,"devices":[signing_key]}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(issued.lobby.state, "admitted");
    assert!(issued.credential.is_some());
    preexisting_role(&service, "alpha", &subject, crgs::Role::Admin).await;
    manage(
        &service,
        "api.admin.alpha.example.test",
        ROOT,
        Role::Admin,
        device,
        user,
        credential,
    )
    .await;
}
