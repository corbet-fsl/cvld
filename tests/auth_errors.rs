#![cfg(feature = "development-gate")]
//! Passkey ceremonies, capacities, restarts and clock extremes on the global door.
mod support;
use cvld::{api::Ceremony, error::Error, service::Door};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::AtomicU64};
use support::*;

const BOOTSTRAP: &str = "synthetic-operator-enrolment-capability";
const UNKNOWN: &str = "00000000-0000-4000-8000-0000000000ff";

async fn ceremony(service: &Running, host: &str, name: &str, body: Value) -> Ceremony {
    serde_json::from_value(client(service, host, None).call(name, body).await.unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_registrations_are_capped() {
    let service = global_tuned(1000, |config| config.pending_capacity = 1).await;
    let anonymous = client(&service, WALLET, None);
    let begin = json!({"bootstrap": null, "passport": null});
    anonymous
        .call("register_begin", begin.clone())
        .await
        .unwrap();
    assert!(matches!(
        anonymous.call("register_begin", begin).await,
        Err(Error::Throttled)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_sign_ins_and_live_sessions_are_capped() {
    let service = global_tuned(1000, |config| config.pending_capacity = 1).await;
    let mut member = enrol(&service, WALLET, None).await;
    let wallet = client(&service, WALLET, None);
    let begin = json!({"user": member.user, "credential": member.credential});
    let start = ceremony(&service, WALLET, "login_begin", begin.clone()).await;
    let assertion = sign_in(WALLET, &mut member.authenticator, &start);
    // One ceremony is pending, so no further ceremony may begin.
    assert!(matches!(
        wallet.call("login_begin", begin).await,
        Err(Error::Throttled)
    ));
    assert!(matches!(
        wallet.call("login_discoverable_begin", json!({})).await,
        Err(Error::Throttled)
    ));
    // The enrolment session already fills the session table.
    assert!(matches!(
        wallet
            .call(
                "login_finish",
                json!({"ceremony": start.ceremony, "credential": assertion})
            )
            .await,
        Err(Error::Throttled)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_refuses_unknown_credentials_other_operators_and_replayed_assertions() {
    let service = global(100).await;
    let mut member = enrol(&service, WALLET, None).await;
    let wallet = client(&service, WALLET, None);
    assert!(matches!(
        wallet
            .call("login_begin", json!({"user": UNKNOWN, "credential": []}))
            .await,
        Err(Error::Unauthorized)
    ));
    // The operator host signs in the operator and nobody else.
    assert!(matches!(
        client(&service, ROOT, None)
            .call(
                "login_begin",
                json!({"user": UNKNOWN, "credential": [1, 2, 3]})
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let begin = json!({"user": member.user, "credential": member.credential});
    let first = ceremony(&service, WALLET, "login_begin", begin.clone()).await;
    let assertion = sign_in(WALLET, &mut member.authenticator, &first);
    wallet
        .call(
            "login_finish",
            json!({"ceremony": first.ceremony, "credential": assertion}),
        )
        .await
        .unwrap();
    // An assertion answers exactly one ceremony.
    let second = ceremony(&service, WALLET, "login_begin", begin).await;
    assert!(matches!(
        wallet
            .call(
                "login_finish",
                json!({"ceremony": second.ceremony, "credential": assertion})
            )
            .await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn operator_enrolment_needs_the_capability_and_admits_one_credential() {
    let service = global(100).await;
    let root = client(&service, ROOT, None);
    let wallet = client(&service, WALLET, None);
    assert!(matches!(
        root.call(
            "register_begin",
            json!({"bootstrap": null, "passport": null})
        )
        .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        root.call(
            "register_begin",
            json!({"bootstrap": "x".repeat(40), "passport": null})
        )
        .await,
        Err(Error::Forbidden)
    ));
    // Members never present a capability, and passports belong to communities.
    assert!(matches!(
        wallet
            .call(
                "register_begin",
                json!({"bootstrap": BOOTSTRAP, "passport": null})
            )
            .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        wallet
            .call(
                "register_begin",
                json!({"bootstrap": null, "passport": {"challenge": "c", "proof": []}})
            )
            .await,
        Err(Error::Invalid)
    ));
    // Two ceremonies may be open, but the second credential is a duplicate.
    let begin = json!({"bootstrap": BOOTSTRAP, "passport": null});
    let first = ceremony(&service, ROOT, "register_begin", begin.clone()).await;
    let second = ceremony(&service, ROOT, "register_begin", begin).await;
    let (_, one) = attest(ROOT, &first);
    let (_, two) = attest(ROOT, &second);
    root.call(
        "register_finish",
        json!({"ceremony": first.ceremony, "credential": one}),
    )
    .await
    .unwrap();
    assert!(matches!(
        root.call(
            "register_finish",
            json!({"ceremony": second.ceremony, "credential": two})
        )
        .await,
        Err(Error::Refused)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn operator_credentials_survive_a_restart_and_a_spent_capability_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = global_config(dir.path(), 100, NOW).await;
    let again = duplicate(&config);
    let first = global_from(tempfile::tempdir().unwrap(), config, NOW).await;
    let mut root = enrol(&first, ROOT, Some(BOOTSTRAP)).await;
    drop(first);
    let clock = Arc::new(TestClock(AtomicU64::new(NOW + 3_600)));
    let door = Door::global(again, clock.clone()).await.unwrap();
    let second = serve(door, clock, tempfile::tempdir().unwrap()).await;
    // The provisioned capability is back after the restart, yet the operator already has a passkey.
    assert!(matches!(
        client(&second, ROOT, None)
            .call(
                "register_begin",
                json!({"bootstrap": BOOTSTRAP, "passport": null})
            )
            .await,
        Err(Error::Refused)
    ));
    let session = login(
        &second,
        ROOT,
        &mut root.authenticator,
        &root.user,
        &root.credential,
    )
    .await;
    client(&second, ROOT, Some(&session))
        .call("logout", json!({}))
        .await
        .unwrap();
    drop(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_dates_outside_the_supported_calendar_are_invalid() {
    // The first instant has no calendar date; the second lies beyond year 9999.
    for now in [i64::MAX as u64, 330_000_000_000] {
        let service = global_at(100, NOW).await;
        service.clock.set(now);
        let wallet = client(&service, WALLET, None);
        let start = ceremony(
            &service,
            WALLET,
            "register_begin",
            json!({"bootstrap": null, "passport": null}),
        )
        .await;
        let (_, credential) = attest(WALLET, &start);
        assert!(matches!(
            wallet
                .call(
                    "register_finish",
                    json!({"ceremony": start.ceremony, "credential": credential})
                )
                .await,
            Err(Error::Invalid)
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn warnings_need_a_known_member_and_a_suspended_member_cannot_pass_a_gate() {
    let service = global(100).await;
    let operator = enrol(&service, ROOT, Some(BOOTSTRAP)).await;
    let root = client(&service, ROOT, Some(&operator.session));
    assert!(matches!(
        root.call("global_warn", json!({"user": UNKNOWN})).await,
        Err(Error::Refused)
    ));
    let member = enrol(&service, WALLET, None).await;
    let wallet = client(&service, WALLET, Some(&member.session));
    wallet.call("development_gate", json!({})).await.unwrap();
    root.call("global_warn", json!({"user": member.user}))
        .await
        .unwrap();
    root.call(
        "global_suspend",
        json!({"user": member.user, "until": (NOW / 86_400 + 5) * 86_400}),
    )
    .await
    .unwrap();
    assert!(matches!(
        wallet.call("development_gate", json!({})).await,
        Err(Error::Refused)
    ));
}
