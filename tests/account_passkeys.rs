//! Actual HTTP management for wallet and operator roles using UV resident keys.
#![cfg(feature = "development-gate")]
mod support;
use cvld::api::*;
use serde_json::json;
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
        .ceremony(begin.options, false, &format!("https://{host}"))
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

async fn scenario(
    service: &Running,
    host: &str,
    other_host: &str,
    role: Role,
    bootstrap: Option<&str>,
) {
    let public = client(service, host, None);
    let begin: Ceremony = serde_json::from_value(
        public
            .call("register_begin", json!({"bootstrap":bootstrap}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut original = Resident::default();
    let mut response = original
        .ceremony(begin.options, true, &format!("https://{host}"))
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
    let begin: AddedPasskey = serde_json::from_value(
        api.call("passkey_add", json!({"step":"begin"}))
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
        .ceremony(options, true, &format!("https://{host}"))
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
    second_api
        .call("passkey_revoke", json!({"credential":original_id}))
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
    second_api
        .call("passkey_revoke", json!({"credential":added_id}))
        .await
        .unwrap();
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
    let (_, _, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    scenario(
        &service,
        ROOT,
        "api.admin.alpha.example.test",
        Role::Root,
        Some("synthetic-root-enrolment-capability"),
    )
    .await;
    scenario(
        &service,
        "api.admin.alpha.example.test",
        ROOT,
        Role::Admin,
        Some("synthetic-admin-enrolment-capability"),
    )
    .await;
}
