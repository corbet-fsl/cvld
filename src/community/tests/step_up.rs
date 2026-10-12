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
    service.clock.set(NOW);
    unchanged(&service, &member).await;
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
