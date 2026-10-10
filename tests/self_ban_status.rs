//! Receipt reads use genuine original resident UV; they never renew membership.
#![cfg(feature = "development-gate")]
mod support;
use cvld::api::*;
use serde_json::{Value, json};
use support::{
    resident::{Resident, strip_prf},
    *,
};

const HOST: &str = "api.alpha.example.test";
struct Owner {
    device: Resident,
    session: Session,
}
async fn discover(service: &Running, host: &str, device: &mut Resident) -> Session {
    let api = client(service, host, None);
    let begin: DiscoverableCeremony = serde_json::from_value(
        api.call("login_discoverable_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let credential = assertion(device, begin.options, host).await;
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
async fn assertion(device: &mut Resident, options: Value, host: &str) -> Value {
    let mut credential = device
        .ceremony(options, false, &format!("https://{host}"))
        .await;
    strip_prf(&mut credential);
    credential
}
async fn owner(service: &Running, host: &str, passport: Option<&cpsd::Passport>) -> Owner {
    let proof = if let Some(passport) = passport {
        Some(presentation(service, host, None, passport).await)
    } else {
        None
    };
    let api = client(service, host, None);
    let begin: Ceremony = serde_json::from_value(
        api.call("register_begin", json!({"passport":proof}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut device = Resident::default();
    let mut credential = device
        .ceremony(begin.options, true, &format!("https://{host}"))
        .await;
    strip_prf(&mut credential);
    api.call(
        "register_finish",
        json!({"ceremony":begin.ceremony,"credential":credential}),
    )
    .await
    .unwrap();
    let session = discover(service, host, &mut device).await;
    Owner { device, session }
}
async fn receipt_begin(service: &Running, bearer: Option<&str>) -> SelfBanStatusChallenge {
    let pending: SelfBanStatusChallenge = serde_json::from_value(
        client(service, HOST, bearer)
            .call("community_self_ban_status_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(pending.options["publicKey"]["userVerification"], "required");
    assert!(
        pending.options["publicKey"]["allowCredentials"]
            .as_array()
            .is_none_or(|ids| ids.is_empty())
    );
    pending
}
async fn receipt(service: &Running, device: &mut Resident, bearer: Option<&str>) -> SelfBanStatus {
    let pending = receipt_begin(service, bearer).await;
    let credential = assertion(device, pending.options, HOST).await;
    let value = client(service, HOST, bearer)
        .call(
            "community_self_ban_status_finish",
            json!({"ceremony":pending.ceremony,"credential":credential}),
        )
        .await
        .unwrap();
    assert_eq!(value.as_object().unwrap().len(), 1);
    serde_json::from_value(value).unwrap()
}
async fn terminate(service: &Running, host: &str, owner: &mut Owner, global: bool) {
    let api = client(service, host, Some(&owner.session.token));
    let begin = if global {
        "global_self_ban_begin"
    } else {
        "community_self_ban_begin"
    };
    let finish = if global {
        "global_self_ban_finish"
    } else {
        "community_self_ban_finish"
    };
    let pending: SelfBanChallenge =
        serde_json::from_value(api.call(begin, json!({})).await.unwrap()).unwrap();
    let credential = assertion(&mut owner.device, pending.options, host).await;
    // Discard the success body: the client retains neither a receipt token nor
    // an immutable-order ID and must inspect the durable outcome independently.
    api.call(
        finish,
        json!({"ceremony":pending.ceremony,"credential":credential}),
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_success_response_is_reconciled_by_fresh_uv_even_with_the_ended_session_bearer() {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut owner = owner(&service, HOST, Some(&passport)).await;
    assert!(
        !receipt(&service, &mut owner.device, Some(&owner.session.token))
            .await
            .self_banned
    );
    terminate(&service, HOST, &mut owner, false).await;
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "lobby",
            json!({})
        )
        .await,
        401
    );
    assert!(
        receipt(&service, &mut owner.device, Some(&owner.session.token))
            .await
            .self_banned
    );
    assert!(receipt(&service, &mut owner.device, None).await.self_banned);
    let pending: DiscoverableCeremony = serde_json::from_value(
        client(&service, HOST, None)
            .call("login_discoverable_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let credential = assertion(&mut owner.device, pending.options, HOST).await;
    assert_ne!(
        call_status(
            &service,
            HOST,
            None,
            "login_finish",
            json!({"ceremony":pending.ceremony,"credential":credential})
        )
        .await,
        200
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "handle_reserve",
            json!({"handle":"receipt_cannot_return"})
        )
        .await,
        401
    );
    let proof = presentation(&service, HOST, None, &passport).await;
    assert_eq!(
        call_status(
            &service,
            HOST,
            None,
            "register_begin",
            json!({"passport":proof})
        )
        .await,
        409
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_proof_and_receipt_proof_cannot_be_substituted_or_replayed() {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut owner = owner(&service, HOST, Some(&passport)).await;
    let api = client(&service, HOST, None);
    let login: DiscoverableCeremony = serde_json::from_value(
        api.call("login_discoverable_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let pending = receipt_begin(&service, None).await;
    let credential = assertion(&mut owner.device, login.options, HOST).await;
    let login_body = json!({"ceremony":login.ceremony,"credential":credential});
    let mut substituted = login_body.clone();
    substituted["ceremony"] = json!(pending.ceremony);
    assert_ne!(
        call_status(
            &service,
            HOST,
            None,
            "community_self_ban_status_finish",
            substituted
        )
        .await,
        200
    );
    api.call("login_finish", login_body).await.unwrap();
    let pending = receipt_begin(&service, None).await;
    let credential = assertion(&mut owner.device, pending.options, HOST).await;
    let body = json!({"ceremony":pending.ceremony,"credential":credential});
    let status: SelfBanStatus = serde_json::from_value(
        api.call("community_self_ban_status_finish", body.clone())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!status.self_banned);
    assert_eq!(
        call_status(
            &service,
            HOST,
            None,
            "community_self_ban_status_finish",
            body.clone()
        )
        .await,
        401
    );
    assert_eq!(
        call_status(&service, HOST, None, "login_finish", body.clone()).await,
        401
    );
    let pending = receipt_begin(&service, None).await;
    let mut old_assertion = body;
    old_assertion["ceremony"] = json!(pending.ceremony);
    assert_ne!(
        call_status(
            &service,
            HOST,
            None,
            "community_self_ban_status_finish",
            old_assertion
        )
        .await,
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_and_expired_login_do_not_turn_receipt_into_a_session_or_bypass_its_deadline() {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut owner = owner(&service, HOST, Some(&passport)).await;
    client(&service, HOST, Some(&owner.session.token))
        .call("logout", json!({}))
        .await
        .unwrap();
    assert!(
        !receipt(&service, &mut owner.device, Some(&owner.session.token))
            .await
            .self_banned
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "lobby",
            json!({})
        )
        .await,
        401
    );
    owner.session = discover(&service, HOST, &mut owner.device).await;
    service.clock.set(owner.session.expires);
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "lobby",
            json!({})
        )
        .await,
        401
    );
    assert!(
        !receipt(&service, &mut owner.device, Some(&owner.session.token))
            .await
            .self_banned
    );
    let pending = receipt_begin(&service, Some(&owner.session.token)).await;
    let credential = assertion(&mut owner.device, pending.options, HOST).await;
    service.clock.set(pending.expires);
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&owner.session.token),
            "community_self_ban_status_finish",
            json!({"ceremony":pending.ceremony,"credential":credential})
        )
        .await,
        401
    );
    assert!(
        !receipt(&service, &mut owner.device, Some(&owner.session.token))
            .await
            .self_banned
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_caller_target_cross_scope_or_foreign_key_can_read_another_members_receipt() {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let alpha = community("alpha", &public).await;
    let beta = community("beta", &public).await;
    let mut original = owner(&alpha, HOST, Some(&passport)).await;
    let (_, other_passport, _) = wallet_passport(&global).await;
    let mut other = owner(&alpha, HOST, Some(&other_passport)).await;
    terminate(&alpha, HOST, &mut original, false).await;
    assert!(!receipt(&alpha, &mut other.device, None).await.self_banned);
    let pending = receipt_begin(&alpha, None).await;
    let credential = assertion(&mut original.device, pending.options, HOST).await;
    let body = json!({"ceremony":pending.ceremony,"credential":credential});
    for host in [ROOT, "api.admin.alpha.example.test"] {
        assert_eq!(
            call_status(
                &alpha,
                host,
                None,
                "community_self_ban_status_begin",
                json!({})
            )
            .await,
            421
        );
        assert_eq!(
            call_status(
                &alpha,
                host,
                None,
                "community_self_ban_status_finish",
                body.clone()
            )
            .await,
            421
        );
    }
    assert_eq!(
        call_status(
            &beta,
            "api.beta.example.test",
            None,
            "community_self_ban_status_finish",
            body.clone()
        )
        .await,
        401
    );
    assert_eq!(
        call_status(
            &alpha,
            "api.beta.example.test",
            None,
            "community_self_ban_status_finish",
            body.clone()
        )
        .await,
        421
    );
    let mut target = body.clone();
    target["subject"] = json!(other.session.user);
    assert_eq!(
        call_status(
            &alpha,
            HOST,
            None,
            "community_self_ban_status_finish",
            target
        )
        .await,
        400
    );
    assert_eq!(
        call_status(
            &alpha,
            HOST,
            None,
            "community_self_ban_status_begin",
            json!({"subject":other.session.user})
        )
        .await,
        400
    );
    let status: SelfBanStatus = serde_json::from_value(
        client(&alpha, HOST, None)
            .call("community_self_ban_status_finish", body)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(status.self_banned);
    // Only a genuine alpha key can answer alpha's ceremony. A separate beta
    // enrolment is not inferred from passport/person equality.
    let beta_owner = owner(&beta, "api.beta.example.test", Some(&passport)).await;
    assert_ne!(beta_owner.session.user, original.session.user);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_wallet_login_can_read_its_own_terminal_status_without_restoring_global_access() {
    let service = global(200).await;
    let mut original = owner(&service, WALLET, None).await;
    let api = client(&service, WALLET, Some(&original.session.token));
    let status: SelfBanStatus =
        serde_json::from_value(api.call("global_self_ban_status", json!({})).await.unwrap())
            .unwrap();
    assert!(
        !status.self_banned,
        "a genuine enrolled wallet can have no cgbl account before its first gate"
    );
    terminate(&service, WALLET, &mut original, true).await;
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&original.session.token),
            "global_self_ban_status",
            json!({})
        )
        .await,
        401
    );
    original.session = discover(&service, WALLET, &mut original.device).await;
    let api = client(&service, WALLET, Some(&original.session.token));
    let value = api.call("global_self_ban_status", json!({})).await.unwrap();
    assert_eq!(value, json!({"self_banned":true}));
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&original.session.token),
            "development_gate",
            json!({})
        )
        .await,
        409
    );
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&original.session.token),
            "passport_challenge",
            json!({})
        )
        .await,
        409
    );
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&original.session.token),
            "global_self_ban_status",
            json!({"subject":"some-other-wallet"})
        )
        .await,
        400
    );
    let other = owner(&service, WALLET, None).await;
    let status: SelfBanStatus = serde_json::from_value(
        client(&service, WALLET, Some(&other.session.token))
            .call("global_self_ban_status", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!status.self_banned);
}
