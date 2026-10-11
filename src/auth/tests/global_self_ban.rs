//! Purpose-specific self-ban confirms real UV WebAuthn, not a login assertion.
use super::*;
use crate::{service::Clock, test_support::TestClock};
use std::sync::atomic::AtomicU64;

async fn enrolled(auth: &mut Auth, device: &mut Resident) -> Session {
    let begin = auth
        .register_begin(start(auth.operator.map(|_| BOOTSTRAP)), NOW)
        .await
        .unwrap();
    let registration = registration(device, begin).await;
    auth.register_finish(registration, NOW).await.unwrap();
    let request = login(auth, device).await;
    auth.login_finish(request, NOW).await.unwrap()
}
async fn confirm(
    auth: &mut Auth,
    session: &Session,
    device: &mut Resident,
    clock: &dyn Clock,
) -> SelfBanConfirmation {
    let challenge = auth
        .begin_global_self_ban(&session.token, NOW, clock)
        .await
        .unwrap();
    assert!(matches!(
        challenge.intent,
        SelfBanIntent::PermanentGlobalSelfBan
    ));
    assert_eq!(challenge.expires, NOW + 300);
    assert_eq!(
        challenge.options["publicKey"]["userVerification"],
        "required"
    );
    let mut credential = device.ceremony(challenge.options, false, ORIGIN).await;
    strip_prf(&mut credential);
    SelfBanConfirmation {
        ceremony: challenge.ceremony,
        credential: serde_json::from_value(credential).unwrap(),
    }
}
fn copy(request: &SelfBanConfirmation) -> SelfBanConfirmation {
    serde_json::from_value(serde_json::to_value(request).unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_live_session_and_passkey_confirm_once_and_never_accept_a_login_proof() {
    let (_directory, database) = database().await;
    let mut auth = auth(&database, None, 4);
    let mut device = Resident::default();
    let session = enrolled(&mut auth, &mut device).await;
    let clock = TestClock(AtomicU64::new(NOW));
    let second = login(&mut auth, &mut device).await;
    let second = auth.login_finish(second, NOW).await.unwrap();
    let request = confirm(&mut auth, &session, &mut device, &clock).await;
    let login_request = login(&mut auth, &mut device).await;
    assert!(matches!(
        auth.finish_global_self_ban(
            &session.token,
            SelfBanConfirmation {
                ceremony: login_request.ceremony.clone(),
                credential: login_request.credential
            },
            NOW,
            &clock
        )
        .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        auth.finish_global_self_ban(&second.token, copy(&request), NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
    let confirmed = auth
        .finish_global_self_ban(&session.token, copy(&request), NOW, &clock)
        .await
        .unwrap();
    assert_eq!(confirmed.user().to_string(), session.user);
    let grant = auth.authenticate(&session.token, NOW).await.unwrap();
    confirmed.validate(&grant, NOW, &clock).unwrap();
    let mut wrong = grant.clone();
    wrong.session_id = [0; 32];
    assert!(matches!(
        confirmed.validate(&wrong, NOW, &clock),
        Err(Error::Unauthorized)
    ));
    let mut wrong = grant.clone();
    wrong.credential = vec![9; 32].into();
    assert!(matches!(
        confirmed.validate(&wrong, NOW, &clock),
        Err(Error::Unauthorized)
    ));
    let mut wrong = grant;
    wrong.user = Uuid::new_v4();
    assert!(matches!(
        confirmed.validate(&wrong, NOW, &clock),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        auth.finish_global_self_ban(&session.token, request, NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
    clock.set(NOW + 300);
    let grant = auth.authenticate(&session.token, NOW + 300).await.unwrap();
    assert!(matches!(
        confirmed.validate(&grant, NOW, &clock),
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_login_assertion_for_the_right_key_cannot_replace_the_self_ban_challenge() {
    let (_directory, database) = database().await;
    let mut auth = auth(&database, None, 4);
    let mut device = Resident::default();
    let session = enrolled(&mut auth, &mut device).await;
    let clock = TestClock(AtomicU64::new(NOW));
    let ban = auth
        .begin_global_self_ban(&session.token, NOW, &clock)
        .await
        .unwrap();
    let login = login(&mut auth, &mut device).await;
    assert!(matches!(
        auth.finish_global_self_ban(
            &session.token,
            SelfBanConfirmation {
                ceremony: ban.ceremony.clone(),
                credential: login.credential
            },
            NOW,
            &clock
        )
        .await,
        Err(Error::Unauthorized)
    ));
    assert!(!auth.self_bans.contains_key(&ban.ceremony));
    let mut request = confirm(&mut auth, &session, &mut device, &clock).await;
    let mut json = serde_json::to_value(&request).unwrap();
    json["credential"]["response"]["signature"] = serde_json::json!("AA");
    request = serde_json::from_value(json).unwrap();
    assert!(matches!(
        auth.finish_global_self_ban(&session.token, request, NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_logged_out_revoked_and_rolled_back_ceremonies_cannot_confirm() {
    for cause in [
        "ceremony-expiry",
        "session-expiry",
        "logout",
        "account-logout",
        "revocation",
        "rollback",
    ] {
        let (_directory, database) = database().await;
        let mut auth = auth(&database, None, 4);
        let mut device = Resident::default();
        let session = enrolled(&mut auth, &mut device).await;
        let clock = TestClock(AtomicU64::new(NOW));
        let request = confirm(&mut auth, &session, &mut device, &clock).await;
        let grant = auth.authenticate(&session.token, NOW).await.unwrap();
        let now = match cause {
            "ceremony-expiry" => NOW + 300,
            "session-expiry" => NOW + 600,
            "logout" => {
                auth.logout(&session.token);
                NOW
            }
            "account-logout" => {
                auth.logout_account(grant.user);
                NOW
            }
            "revocation" => {
                let keys = auth.passkeys.clone();
                let id = grant.credential.clone();
                tokio::task::spawn_blocking(move || keys.revoke(grant.user, &id))
                    .await
                    .unwrap()
                    .unwrap();
                NOW
            }
            "rollback" => {
                clock.set(NOW - 1);
                NOW
            }
            _ => unreachable!(),
        };
        if cause != "rollback" {
            clock.set(now);
        }
        assert!(
            matches!(
                auth.finish_global_self_ban(&session.token, request, now, &clock)
                    .await,
                Err(Error::Unauthorized)
            ),
            "{cause}"
        );
        assert!(
            !auth.sessions.contains_key(&session.token)
                || cause == "ceremony-expiry"
                || cause == "rollback"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replacement_is_session_local_and_operators_cannot_construct_self_ban_authority() {
    let (_directory, database) = database().await;
    let clock = TestClock(AtomicU64::new(NOW));
    let mut auth = auth(&database, None, 4);
    let mut device = Resident::default();
    let first = enrolled(&mut auth, &mut device).await;
    let second = login(&mut auth, &mut device).await;
    let second = auth.login_finish(second, NOW).await.unwrap();
    let stale = confirm(&mut auth, &first, &mut device, &clock).await;
    let other = confirm(&mut auth, &second, &mut device, &clock).await;
    let current = confirm(&mut auth, &first, &mut device, &clock).await;
    assert_eq!(auth.self_bans.len(), 2);
    assert!(matches!(
        auth.finish_global_self_ban(&first.token, stale, NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(
        auth.finish_global_self_ban(&second.token, other, NOW, &clock)
            .await
            .is_ok()
    );
    assert!(
        auth.finish_global_self_ban(&first.token, current, NOW, &clock)
            .await
            .is_ok()
    );
    let mut root = super::auth(&database, Some(Uuid::new_v4()), 4);
    let root_session = enrolled(&mut root, &mut Resident::default()).await;
    assert!(matches!(
        root.begin_global_self_ban(&root_session.token, NOW, &clock)
            .await,
        Err(Error::Forbidden)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_monotonic_deadline_survives_successful_confirmation_under_a_stalled_wall_clock() {
    let (_directory, database) = database().await;
    let mut auth = Auth::new(keys(&database), Role::Member, None, None, 4, 3).unwrap();
    let mut device = Resident::default();
    let session = enrolled(&mut auth, &mut device).await;
    let clock = TestClock(AtomicU64::new(NOW));
    let challenge = auth
        .begin_global_self_ban(&session.token, NOW, &clock)
        .await
        .unwrap();
    assert_eq!(challenge.expires, NOW + 3);
    let mut credential = device.ceremony(challenge.options, false, ORIGIN).await;
    strip_prf(&mut credential);
    tokio::time::sleep(std::time::Duration::from_millis(1800)).await;
    let confirmed = auth
        .finish_global_self_ban(
            &session.token,
            SelfBanConfirmation {
                ceremony: challenge.ceremony,
                credential: serde_json::from_value(credential).unwrap(),
            },
            NOW,
            &clock,
        )
        .await
        .unwrap();
    let grant = auth.authenticate(&session.token, NOW).await.unwrap();
    confirmed.validate(&grant, NOW, &clock).unwrap();
    struct DelayedClock;
    impl Clock for DelayedClock {
        fn now(&self) -> u64 {
            std::thread::sleep(std::time::Duration::from_millis(1400));
            NOW
        }
    }
    // Wall time and the session remain unchanged; only the original intent's
    // monotonic deadline can reject authority. It must also be checked after
    // obtaining the wall-clock sample, which can itself wait or be descheduled.
    assert_eq!(clock.now(), NOW);
    assert!(matches!(
        confirmed.validate(&grant, NOW, &DelayedClock),
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirmed_self_ban_retains_the_fresh_reauthentication_clock_floor() {
    let (_directory, database) = database().await;
    let mut auth = auth(&database, None, 4);
    let mut device = Resident::default();
    let session = enrolled(&mut auth, &mut device).await;
    let clock = TestClock(AtomicU64::new(NOW));
    let request = confirm(&mut auth, &session, &mut device, &clock).await;
    let confirmed = auth
        .finish_global_self_ban(&session.token, request, NOW, &clock)
        .await
        .unwrap();
    // A database wait can finish after the original ceremony observation.
    // Falling back toward that older time must not reauthorize its write.
    clock.set(NOW + 20);
    let observed = clock.now();
    let grant = auth.authenticate(&session.token, observed).await.unwrap();
    clock.set(NOW + 15);
    assert!(matches!(
        confirmed.validate(&grant, observed, &clock),
        Err(Error::Unauthorized)
    ));
    clock.set(NOW + 21);
    assert_eq!(
        confirmed.validate(&grant, observed, &clock).unwrap(),
        NOW + 21
    );
    let mut expired = grant;
    expired.expires = NOW + 21;
    assert!(matches!(
        confirmed.validate(&expired, observed, &clock),
        Err(Error::Unauthorized)
    ));
}
