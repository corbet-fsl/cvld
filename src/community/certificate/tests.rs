//! Genuine Policy mutex scheduling at the final output boundary.
use super::*;
use crate::test_support as support;
use std::time::Duration;
use support::*;
use webauthn_authenticator_rs::AuthenticatorBackend;

const HOST: &str = "api.alpha.example.test";

struct Fixture {
    _http: Running,
    service: CommunityService,
    session: Session,
    clock: Arc<TestClock>,
    member: String,
}
impl Fixture {
    async fn new() -> Self {
        let global = global(100).await;
        let (_, passport, public) = wallet_passport(&global).await;
        let http = community("alpha", &public).await;
        let mut registered = enrol_community(&http, HOST, &passport).await;
        let config =
            CommunityConfig::read(http.dir.path().join("config.json").to_str().unwrap()).unwrap();
        let db = crlt::Db::open(crlt::Config::new(&config.database_url, ""))
            .await
            .unwrap();
        let clock = http.clock.clone();
        // Reopen genuine durable owners, then create this service's session by
        // verifying the actual registered software key, never inserting a grant.
        let mut service = CommunityService::open(&db, config, clock.clone())
            .await
            .unwrap();
        let begin = service
            .login_begin(
                LoginStart {
                    user: registered.user,
                    credential: registered.credential,
                },
                NOW,
            )
            .await
            .unwrap();
        let options: ckyh::RequestChallengeResponse =
            serde_json::from_value(begin.options).unwrap();
        let credential = registered
            .authenticator
            .perform_auth(
                ckyh::Url::parse(&format!("https://{HOST}")).unwrap(),
                options.public_key,
                300_000,
            )
            .unwrap();
        let session = service
            .login_finish(
                LoginFinish {
                    ceremony: begin.ceremony,
                    credential: credential.into(),
                },
                NOW,
            )
            .await
            .unwrap();
        let member = passport
            .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
            .to_hex();
        Self {
            _http: http,
            service,
            session,
            clock,
            member,
        }
    }
}

#[derive(Clone, Copy)]
enum Completion {
    Current,
    Expired,
    Rollback,
    Revoked,
}

async fn gated_completion(completion: Completion) {
    let f = Fixture::new().await;
    let policy = f.service.facade.policy();
    // Prepare only genuine original outputs. The private production finisher
    // performs the same final check used by the endpoint, under its real mutex.
    let issued = f.service.certificate(&f.session.token, NOW).await.unwrap();
    assert_eq!(issued.checked_at, NOW);
    let bytes = issued.bytes;
    let (grant, auth) = f
        .service
        .authenticate_current(&f.session.token, NOW)
        .await
        .unwrap();
    let held = policy.lock().await;
    let mut retrieval = Box::pin(
        f.service
            .final_certificate(&f.session.token, grant, bytes, NOW),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut retrieval)
            .await
            .is_err()
    );
    match completion {
        Completion::Current => f.clock.set(NOW + 20),
        Completion::Expired => f.clock.set(f.session.expires),
        Completion::Rollback => f.clock.set(NOW - 1),
        Completion::Revoked => {
            f.service
                .facade
                .membership()
                .revoke_passkey(&auth, auth.credential_id().clone())
                .await
                .unwrap();
        }
    }
    drop(held);
    let result = retrieval.await;
    match completion {
        Completion::Current => {
            let completed = result.unwrap();
            assert_eq!(completed.checked_at, NOW + 20);
            let bytes = completed.bytes;
            let guard = policy.lock().await;
            ckyh::certificate::verify(guard.key_ring().unwrap(), &bytes, &f.member, NOW + 20)
                .unwrap();
        }
        Completion::Expired | Completion::Rollback | Completion::Revoked => {
            assert!(matches!(result, Err(Error::Unauthorized)));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn original_final_policy_lock_releases_to_genuine_certificate_output() {
    gated_completion(Completion::Current).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn exclusive_session_expiry_during_original_final_policy_wait_refuses_output() {
    gated_completion(Completion::Expired).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn clock_rollback_during_original_final_policy_wait_refuses_output() {
    gated_completion(Completion::Rollback).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn actual_current_passkey_revocation_during_original_final_policy_wait_refuses_output() {
    gated_completion(Completion::Revoked).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_owner_completion_floor_survives_cross_owner_clock_regression() {
    let f = Fixture::new().await;
    let (grant, auth) = f
        .service
        .authenticate_current(&f.session.token, NOW)
        .await
        .unwrap();
    // Relative to an outer start of 10, the original owner completes at 30,
    // then the outer clock rolls back to 25. It remains after the outer start.
    f.clock.set(NOW + 20);
    let issued = f
        .service
        .facade
        .passkey_certificate(&auth, NOW)
        .await
        .unwrap();
    assert_eq!(issued.checked_at(), NOW + 20);
    f.clock.set(NOW + 15);
    assert!(matches!(
        f.service
            .finish_issued_certificate(&f.session.token, grant, issued, NOW)
            .await,
        Err(Error::Unauthorized)
    ));
}
