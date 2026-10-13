//! A fresh user-verifying assertion is single use, short lived and bound to the
//! exact action; every refusal leaves the account unchanged.
use super::*;
use crate::test_support as support;
use serde_json::{Value, json};
use support::*;
use webauthn_authenticator_rs::AuthenticatorBackend;

const HOST: &str = "api.alpha.example.test";

async fn fixture() -> (Running, Running, Member) {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let member = enrol_community(&service, HOST, &passport).await;
    (global, service, member)
}

async fn status(service: &Running, member: &Member, action: &str, body: Value) -> u16 {
    call_status(service, HOST, Some(&member.session), action, body).await
}

/// The account is exactly as enrolment left it.
async fn unchanged(service: &Running, member: &Member) {
    let c = client(service, HOST, Some(&member.session));
    let list: PasskeyList =
        serde_json::from_value(c.call("passkey_list", json!({})).await.unwrap()).unwrap();
    assert_eq!(list.passkeys.len(), 1);
    assert!(!list.passkeys[0].revoked);
    let keys: DeviceKeys =
        serde_json::from_value(c.call("device_keys", json!({})).await.unwrap()).unwrap();
    assert_eq!(keys.keys, vec![member.signing_key]);
}

async fn proof(service: &Running, member: &mut Member, action: Value) -> Value {
    step_up(
        service,
        HOST,
        &member.session.clone(),
        &mut member.authenticator,
        action,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_action_is_refused_without_a_proof() {
    let (_global, service, member) = fixture().await;
    assert_eq!(
        status(&service, &member, "passkey_add", json!({"step":"begin"})).await,
        403
    );
    assert_eq!(
        status(
            &service,
            &member,
            "passkey_revoke",
            json!({"credential":member.credential})
        )
        .await,
        403
    );
    assert_eq!(
        status(
            &service,
            &member,
            "device_authorize",
            json!({"key":vec![7;32]})
        )
        .await,
        403
    );
    unchanged(&service, &member).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proof_is_single_use_and_expires() {
    let (_global, service, mut member) = fixture().await;
    let used = proof(&service, &mut member, json!({"kind":"passkey_add"})).await;
    let body = json!({"step":"begin","step_up":used});
    assert_eq!(
        status(&service, &member, "passkey_add", body.clone()).await,
        200
    );
    assert_eq!(status(&service, &member, "passkey_add", body).await, 401);
    let stale = proof(&service, &mut member, json!({"kind":"passkey_add"})).await;
    unchanged(&service, &member).await;
    service.clock.set(NOW + 61);
    assert_eq!(
        status(
            &service,
            &member,
            "passkey_add",
            json!({"step":"begin","step_up":stale})
        )
        .await,
        401
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proof_for_one_action_or_target_is_refused_for_any_other() {
    let (_global, service, mut member) = fixture().await;
    let device = proof(
        &service,
        &mut member,
        json!({"kind":"device_authorize","key":vec![7;32]}),
    )
    .await;
    assert_eq!(
        status(
            &service,
            &member,
            "device_authorize",
            json!({"key":vec![8;32],"step_up":device})
        )
        .await,
        401
    );
    // The probe consumed it: even the exact action no longer accepts it.
    assert_eq!(
        status(
            &service,
            &member,
            "device_authorize",
            json!({"key":vec![7;32],"step_up":device})
        )
        .await,
        401
    );
    let revoke = proof(
        &service,
        &mut member,
        json!({"kind":"passkey_revoke","credential":vec![9;16]}),
    )
    .await;
    assert_eq!(
        status(
            &service,
            &member,
            "passkey_revoke",
            json!({"credential":member.credential,"step_up":revoke})
        )
        .await,
        401
    );
    let add = proof(&service, &mut member, json!({"kind":"passkey_add"})).await;
    assert_eq!(
        status(
            &service,
            &member,
            "passkey_revoke",
            json!({"credential":member.credential,"step_up":add})
        )
        .await,
        401
    );
    unchanged(&service, &member).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_assertion_without_user_verification_is_refused() {
    let (_global, service, mut member) = fixture().await;
    let begin: StepUpChallenge = serde_json::from_value(
        client(&service, HOST, Some(&member.session))
            .call("step_up_begin", json!({"action":{"kind":"passkey_add"}}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut options = begin.options;
    options["publicKey"]["userVerification"] = json!("discouraged");
    let challenge: ckyh::RequestChallengeResponse = serde_json::from_value(options).unwrap();
    let credential = member
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&format!("https://{HOST}")).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    assert_eq!(
        status(
            &service,
            &member,
            "passkey_add",
            json!({"step":"begin","step_up":{"ceremony":begin.ceremony,"credential":credential}})
        )
        .await,
        401
    );
    unchanged(&service, &member).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_revoked_after_the_challenge_cannot_complete_it() {
    let (_global, service, mut member) = fixture().await;
    let pending = proof(&service, &mut member, json!({"kind":"passkey_add"})).await;
    {
        let mut community = service.door.community_backend().unwrap().lock().await;
        let (_, auth) = community.authenticate(&member.session, NOW).await.unwrap();
        community
            .facade
            .membership()
            .revoke_passkey(&auth, member.credential.clone().into())
            .await
            .unwrap();
    }
    assert_eq!(
        status(
            &service,
            &member,
            "passkey_add",
            json!({"step":"begin","step_up":pending})
        )
        .await,
        401
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_actions_need_their_own_proof_and_never_substitute_a_live_key() {
    let (_global, service, mut member) = fixture().await;
    let key = vec![7u8; 32];
    let signing = member.signing_key;
    for (action, body) in [
        ("device_pair_authorize", json!({"key": key})),
        ("device_revoke", json!({"key": signing})),
    ] {
        assert_eq!(status(&service, &member, action, body).await, 403);
    }
    // Nothing is pending, so nothing can be confirmed.
    assert_ne!(
        status(&service, &member, "device_confirm", json!({"key": key})).await,
        200
    );
    // This passkey already has a live key: a pending one is refused, not substituted.
    let used = proof(
        &service,
        &mut member,
        json!({"kind":"device_authorize","key":key}),
    )
    .await;
    assert_ne!(
        status(
            &service,
            &member,
            "device_pair_authorize",
            json!({"key": key, "step_up": used})
        )
        .await,
        200
    );
    unchanged(&service, &member).await;
    // A revocation proof for another key never opens this one; its own does, once.
    let other = proof(
        &service,
        &mut member,
        json!({"kind":"device_revoke","key":key}),
    )
    .await;
    assert_eq!(
        status(
            &service,
            &member,
            "device_revoke",
            json!({"key": signing, "step_up": other})
        )
        .await,
        401
    );
    unchanged(&service, &member).await;
    let own = proof(
        &service,
        &mut member,
        json!({"kind":"device_revoke","key":signing}),
    )
    .await;
    assert_eq!(
        status(
            &service,
            &member,
            "device_revoke",
            json!({"key": signing, "step_up": own})
        )
        .await,
        200
    );
    let c = client(&service, HOST, Some(&member.session));
    let keys: DeviceKeys =
        serde_json::from_value(c.call("device_keys", json!({})).await.unwrap()).unwrap();
    assert!(keys.keys.is_empty());
}

/// The existing device adds the new device's passkey (with its own step-up) and the new
/// device signs in with it. Returns the new passkey's id, authenticator and session.
async fn add_second_passkey(
    service: &Running,
    member: &mut Member,
) -> (
    Vec<u8>,
    webauthn_authenticator_rs::softtoken::SoftToken,
    String,
) {
    use webauthn_authenticator_rs::softtoken::SoftToken;
    let used = proof(service, member, json!({"kind":"passkey_add"})).await;
    let c = client(service, HOST, Some(&member.session));
    let began: AddedPasskey = serde_json::from_value(
        c.call("passkey_add", json!({"step":"begin","step_up":used}))
            .await
            .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Challenge {
        ceremony, options, ..
    } = began
    else {
        panic!("challenge")
    };
    let mut token = SoftToken::new(true).unwrap().0;
    let mut options: ckyh::CreationChallengeResponse = serde_json::from_value(options).unwrap();
    options
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let response: ckyh::RegisterPublicKeyCredential = token
        .perform_register(
            ckyh::Url::parse(&format!("https://{HOST}")).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap()
        .into();
    let credential = response.raw_id.as_ref().to_vec();
    c.call(
        "passkey_add",
        json!({"step":"finish","ceremony":ceremony,"credential":response}),
    )
    .await
    .unwrap();
    let session = login(service, HOST, &mut token, &member.user, &credential).await;
    (credential, token, session)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_devices_key_goes_live_only_after_the_existing_device_approves_it() {
    let (_global, service, mut member) = fixture().await;
    let (_credential, mut token, session) = add_second_passkey(&service, &mut member).await;
    let key = [9u8; 32];
    let old = member.signing_key;
    let keys_of = |session: String| {
        let service = &service;
        async move {
            let c = client(service, HOST, Some(&session));
            let keys: DeviceKeys =
                serde_json::from_value(c.call("device_keys", json!({})).await.unwrap()).unwrap();
            keys.keys
        }
    };
    let on_new = |action: &'static str, body: Value| {
        let (service, session) = (&service, session.clone());
        async move { call_status(service, HOST, Some(&session), action, body).await }
    };
    // The new device authorizes its own key under its own passkey: pending, not live.
    let own = step_up(
        &service,
        HOST,
        &session,
        &mut token,
        json!({"kind":"device_authorize","key":key}),
    )
    .await;
    assert_eq!(
        on_new("device_pair_authorize", json!({"key": key, "step_up": own})).await,
        200
    );
    assert_eq!(keys_of(session.clone()).await, vec![old]);
    // Without the existing device's approval the key stays pending.
    assert_ne!(on_new("device_confirm", json!({"key": key})).await, 200);
    // The new device cannot approve its own key; an approval needs its own fresh step-up.
    let self_approve = step_up(
        &service,
        HOST,
        &session,
        &mut token,
        json!({"kind":"device_approve","key":key}),
    )
    .await;
    assert_ne!(
        on_new(
            "device_approve",
            json!({"key": key, "step_up": self_approve})
        )
        .await,
        200
    );
    assert_eq!(
        status(&service, &member, "device_approve", json!({"key": key})).await,
        403
    );
    // The existing device approves; the new device then confirms and the key is live.
    let approve = proof(
        &service,
        &mut member,
        json!({"kind":"device_approve","key":key}),
    )
    .await;
    assert_eq!(
        status(
            &service,
            &member,
            "device_approve",
            json!({"key": key, "step_up": approve})
        )
        .await,
        200
    );
    assert_eq!(on_new("device_confirm", json!({"key": key})).await, 200);
    let mut live = keys_of(session.clone()).await;
    live.sort();
    let mut expected = vec![old, key];
    expected.sort();
    assert_eq!(live, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_aborted_pairing_leaves_no_approved_passkey_once_the_existing_device_revokes_it() {
    let (_global, service, mut member) = fixture().await;
    let (credential, _token, _session) = add_second_passkey(&service, &mut member).await;
    let session = member.session.clone();
    let listed = || {
        let c = client(&service, HOST, Some(&session));
        async move {
            let list: PasskeyList =
                serde_json::from_value(c.call("passkey_list", json!({})).await.unwrap()).unwrap();
            list.passkeys
        }
    };
    assert_eq!(listed().await.len(), 2);
    // Abort: a fresh step-up for exactly that passkey revokes it.
    let revoke = proof(
        &service,
        &mut member,
        json!({"kind":"passkey_revoke","credential":credential}),
    )
    .await;
    assert_eq!(
        status(
            &service,
            &member,
            "passkey_revoke",
            json!({"credential": credential, "step_up": revoke})
        )
        .await,
        200
    );
    let after = listed().await;
    assert_eq!(after.iter().filter(|p| p.revoked).count(), 1);
    assert!(after.iter().any(|p| p.current && !p.revoked));
}
