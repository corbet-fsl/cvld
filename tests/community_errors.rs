#![cfg(feature = "development-gate")]
//! Community enrolment, issuance, capacity and restart failures over the real HTTP door.
mod support;
use cvld::{
    api::{Ceremony, PresentationChallenge, PresentationInput},
    error::Error,
    service::Door,
};
use serde_json::json;
use std::sync::{Arc, atomic::AtomicU64};
use support::*;

async fn begin_registration(service: &Running, host: &str, passport: &cpsd::Passport) -> Ceremony {
    let input = presentation(service, host, None, passport).await;
    serde_json::from_value(
        client(service, host, None)
            .call("register_begin", json!({"passport": input}))
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_refuses_roles_owned_challenges_and_mismatched_proofs() {
    let world = global(100).await;
    let (_, passport, public) = wallet_passport(&world).await;
    let service = community("misuse", &public).await;
    let host = "api.misuse.example.test";
    let anonymous = client(&service, host, None);
    assert!(matches!(
        anonymous
            .call(
                "register_begin",
                json!({"bootstrap": "x", "passport": null})
            )
            .await,
        Err(Error::Forbidden)
    ));
    let member = enrol_community(&service, host, &passport).await;
    // A challenge reserved for a signed-in member cannot start a registration.
    let owned = presentation(&service, host, Some(&member.session), &passport).await;
    assert!(matches!(
        anonymous
            .call("register_begin", json!({"passport": owned}))
            .await,
        Err(Error::Forbidden)
    ));
    // A proof answers exactly the challenge it was built for.
    let first = presentation(&service, host, None, &passport).await;
    let second = presentation(&service, host, None, &passport).await;
    let crossed = PresentationInput {
        challenge: first.challenge,
        proof: second.proof,
    };
    assert!(matches!(
        anonymous
            .call("register_begin", json!({"passport": crossed}))
            .await,
        Err(Error::Refused)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_for_another_ceremony_cannot_finish_a_registration() {
    let world = global(100).await;
    let (_, passport_a, public) = wallet_passport(&world).await;
    let (_, passport_b, _) = wallet_passport(&world).await;
    let service = community("crossed", &public).await;
    let host = "api.crossed.example.test";
    let start_a = begin_registration(&service, host, &passport_a).await;
    let start_b = begin_registration(&service, host, &passport_b).await;
    let (_, credential_b) = attest(host, &start_b);
    assert!(matches!(
        client(&service, host, None)
            .call(
                "register_finish",
                json!({"ceremony": start_a.ceremony, "credential": credential_b})
            )
            .await,
        Err(Error::Refused)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_issue_refuses_foreign_challenges_and_malformed_proofs() {
    let world = global(100).await;
    let (_, passport, public) = wallet_passport(&world).await;
    let service = community("issuing", &public).await;
    let host = "api.issuing.example.test";
    let member = enrol_community(&service, host, &passport).await;
    let signed_in = client(&service, host, Some(&member.session));
    // An anonymous challenge belongs to nobody, so a member cannot spend it.
    let anonymous = presentation(&service, host, None, &passport).await;
    assert!(matches!(
        signed_in
            .call(
                "credential_issue",
                json!({"presentation": anonymous, "devices": [member.signing_key]})
            )
            .await,
        Err(Error::Forbidden)
    ));
    let owned: PresentationChallenge = serde_json::from_value(
        signed_in
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        signed_in
            .call(
                "credential_issue",
                json!({"presentation": {"challenge": owned.challenge, "proof": [1, 2, 3]}, "devices": []})
            )
            .await,
        Err(Error::Invalid)
    ));
    // A voucher that is not bound to this member never passes its gate.
    assert!(
        signed_in
            .call(
                "gate_voucher",
                json!({"id": "v", "member_binding": "not-a-binding", "valid_until": NOW + 100, "signature": [1, 2, 3]})
            )
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn outstanding_challenges_are_capped() {
    let world = global(100).await;
    let (_, _, public) = wallet_passport(&world).await;
    let service = community_tuned("capped", &public, |config| config.pending_capacity = 1).await;
    let anonymous = client(&service, "api.capped.example.test", None);
    anonymous
        .call("presentation_challenge", json!({}))
        .await
        .unwrap();
    assert!(matches!(
        anonymous.call("presentation_challenge", json!({})).await,
        Err(Error::Throttled)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_registrations_are_capped() {
    let world = global(100).await;
    let (_, passport, public) = wallet_passport(&world).await;
    let service = community_tuned("queued", &public, |config| config.pending_capacity = 1).await;
    let host = "api.queued.example.test";
    begin_registration(&service, host, &passport).await;
    assert!(matches!(
        client(&service, host, None)
            .call(
                "register_begin",
                json!({"bootstrap": null, "passport": null})
            )
            .await,
        Err(Error::Throttled)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_sign_ins_and_live_sessions_are_capped() {
    let world = global(100).await;
    let (_, passport, public) = wallet_passport(&world).await;
    let service = community_tuned("narrow", &public, |config| config.pending_capacity = 2).await;
    let host = "api.narrow.example.test";
    let mut member = enrol_community(&service, host, &passport).await;
    // A second sign-in fills the session table (enrolment created the first).
    login(
        &service,
        host,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    let anonymous = client(&service, host, None);
    let begin = json!({"user": member.user, "credential": member.credential});
    let start: Ceremony =
        serde_json::from_value(anonymous.call("login_begin", begin.clone()).await.unwrap())
            .unwrap();
    let assertion = sign_in(host, &mut member.authenticator, &start);
    anonymous.call("login_begin", begin.clone()).await.unwrap();
    assert!(matches!(
        anonymous.call("login_begin", begin).await,
        Err(Error::Throttled)
    ));
    assert!(matches!(
        anonymous.call("login_discoverable_begin", json!({})).await,
        Err(Error::Throttled)
    ));
    assert!(matches!(
        anonymous
            .call(
                "login_finish",
                json!({"ceremony": start.ceremony, "credential": assertion})
            )
            .await,
        Err(Error::Throttled)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_needs_a_known_credential_and_a_representable_clock() {
    let world = global(100).await;
    let (_, _, public) = wallet_passport(&world).await;
    let service = community("clocked", &public).await;
    let anonymous = client(&service, "api.clocked.example.test", None);
    let unknown = json!({"user": "00000000-0000-4000-8000-0000000000bb", "credential": []});
    assert!(matches!(
        anonymous.call("login_begin", unknown).await,
        Err(Error::Unauthorized)
    ));
    // Membership time must fit a signed 64-bit counter.
    service.clock.set(u64::MAX);
    assert!(matches!(
        anonymous
            .call(
                "login_begin",
                json!({"user": "00000000-0000-4000-8000-0000000000bb", "credential": [1, 2, 3]})
            )
            .await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn maintenance_republishes_stale_snapshots() {
    let world = global(100).await;
    let (_, _, public) = wallet_passport(&world).await;
    let service = community("stale", &public).await;
    service.clock.set(NOW + 86_400 + 60);
    service.door.maintain().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn members_and_policy_survive_a_restart() {
    let world = global(100).await;
    let (_, passport, public) = wallet_passport(&world).await;
    let dir = tempfile::tempdir().unwrap();
    let config = community_config(dir.path(), "restart", &public, 100);
    let again = duplicate(&config);
    let host = "api.restart.example.test";
    let first = community_from(tempfile::tempdir().unwrap(), config).await;
    let mut member = enrol_community(&first, host, &passport).await;
    drop(first);
    let clock = Arc::new(TestClock(AtomicU64::new(NOW + 3_600)));
    let door = Door::community(again, clock.clone()).await.unwrap();
    let second = serve(door, clock, tempfile::tempdir().unwrap()).await;
    let session = login(
        &second,
        host,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    let lobby: cvld::api::Lobby = serde_json::from_value(
        client(&second, host, Some(&session))
            .call("lobby", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        lobby.member_id,
        passport
            .pseudonym(&cpsd::CommunityId::new("restart").unwrap())
            .to_hex()
    );
    drop(dir);
}
