//! Real enrollment/authentication with held owner leases and clock substitution.
use super::*;
use crate::payment_test_support as payment_support;
use crate::service::{Clock, Door};
use crate::test_support as support;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use support::*;
use webauthn_authenticator_rs::{AuthenticatorBackend as _, softtoken::SoftToken};

#[path = "../../../tests/cases/production_journey/contacts.rs"]
mod contacts;
#[allow(dead_code)]
#[path = "../../../tests/cases/production_journey/payment.rs"]
mod payment;
#[allow(dead_code)]
#[path = "../../../tests/cases/initial_creation/routes.rs"]
mod routes;

const HOST: &str = "api.alpha.example.test";
const SEED: [u8; 32] = [17; 32];
const PUBLICATION: [u8; 32] = [29; 32];

struct FixedClock(u64);
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_ceremony_metadata_matches_the_same_pending_consumed_by_real_finish() {
    let (global, _, cohort) = contacts::production(true).await;
    let (_, passport, public) = contacts::wallet(&global, cohort).await;
    let wire = payment_support::Wire::new(payment_support::Reply::Success);
    let running = payment::community(&public, wire).await;
    let passport = presentation(&running, HOST, None, &passport).await;
    let mut service = running.door.community_backend().unwrap().lock().await;
    running.clock.set(NOW + 2);
    let initial = service
        .initial_registration_begin(
            InitialRegistrationBegin {
                passport,
                seed: SEED,
            },
            NOW,
        )
        .await
        .unwrap();
    let pending = service.registrations.get(&initial.ceremony).unwrap();
    assert_eq!(initial.user, pending.user.to_string());
    assert_eq!(initial.expires_at, pending.until);
    assert_eq!(initial.checked_at, running.clock.now());
    assert_eq!(initial.checked_at, NOW + 2);
    // The response reports the original retained deadline, without reanchoring
    // it to the later authoritative output sample.
    assert_eq!(initial.expires_at, NOW + 300);
    let mut authenticator = SoftToken::new(true).unwrap().0;
    let options: ckyh::CreationChallengeResponse = serde_json::from_value(initial.options).unwrap();
    let mut options = options.public_key;
    options
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let credential = authenticator
        .perform_register(
            ckyh::Url::parse(&format!("https://{HOST}")).unwrap(),
            options,
            300_000,
        )
        .unwrap();
    let user = service
        .register_finish(
            RegisterFinish {
                ceremony: initial.ceremony.clone(),
                credential: serde_json::from_value(serde_json::to_value(credential).unwrap())
                    .unwrap(),
            },
            NOW + 2,
        )
        .await
        .unwrap();
    assert_eq!(user.user, initial.user);
    assert!(!service.registrations.contains_key(&initial.ceremony));
}

#[derive(Clone)]
struct CreationObserver {
    db: crlt::Db,
    runtime: tokio::runtime::Handle,
    authentication: ckyh::Authentication,
    expires_at: u64,
}
impl CreationObserver {
    fn keys(&self) -> ckyh::Passkeys<ckyh::LibsqlStore> {
        ckyh::Passkeys::new(
            ckyh::LibsqlStore::new(&self.db, "alpha", self.runtime.clone()).unwrap(),
            "alpha",
            "alpha.example.test",
            &[
                ckyh::Url::parse("https://api.alpha.example.test").unwrap(),
                ckyh::Url::parse("https://alpha.example.test").unwrap(),
                ckyh::Url::parse("https://vault.alpha.example.test").unwrap(),
            ],
        )
        .unwrap()
    }
}
struct PostBindExpiryClock {
    now: AtomicU64,
    observer: Mutex<Option<CreationObserver>>,
    committed: AtomicBool,
}
impl Clock for PostBindExpiryClock {
    fn now(&self) -> u64 {
        let observer = self.observer.lock().unwrap().clone();
        if let Some(observer) = observer {
            // LibsqlStore is synchronous: run it on an ordinary thread, with
            // the real runtime and original live authentication. No guessed
            // call count or replacement credential controls this observation.
            let expires_at = observer.expires_at;
            let committed = std::thread::spawn(move || {
                observer
                    .keys()
                    .initial_creation(&observer.authentication)
                    .unwrap()
                    .publication()
                    == Some(PUBLICATION)
            })
            .join()
            .unwrap();
            if committed {
                self.committed.store(true, Ordering::SeqCst);
                self.now.store(expires_at, Ordering::SeqCst);
                self.observer.lock().unwrap().take();
            }
        }
        self.now.load(Ordering::SeqCst)
    }
}

async fn original_login(service: &mut CommunityService, member: &mut Member, now: u64) -> Session {
    let start = service
        .login_begin(
            LoginStart {
                user: member.user.clone(),
                credential: member.credential.clone(),
            },
            now,
        )
        .await
        .unwrap();
    let options: ckyh::RequestChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = member
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&format!("https://{HOST}")).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap();
    service
        .login_finish(
            LoginFinish {
                ceremony: start.ceremony,
                credential: serde_json::from_value(serde_json::to_value(credential).unwrap())
                    .unwrap(),
            },
            now,
        )
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaf_expiry_after_actual_bind_returns_reconcile_and_fresh_uv_reads_the_winner() {
    let mut f = routes::fixture().await;
    let existing = f.service.door.community_backend().unwrap().lock().await;
    let db = existing.db.clone();
    let config = serde_json::from_value(serde_json::to_value(&existing.config).unwrap()).unwrap();
    drop(existing);
    let clock = Arc::new(PostBindExpiryClock {
        now: AtomicU64::new(NOW),
        observer: Mutex::new(None),
        committed: AtomicBool::new(false),
    });
    let mut service = CommunityService::open(&db, config, clock.clone())
        .await
        .unwrap();
    let session = original_login(&mut service, &mut f.member, NOW).await;
    let (_, authentication) = service
        .authenticate_current(&session.token, NOW)
        .await
        .unwrap();
    *clock.observer.lock().unwrap() = Some(CreationObserver {
        db,
        runtime: tokio::runtime::Handle::current(),
        authentication: authentication.as_ref().clone(),
        expires_at: session.expires,
    });
    // Call the actual host handler directly. The generic publication wrapper
    // must not mask a wrong Refused mapping from the leaf's post-commit error.
    let result = service
        .initial_creation(
            &session.token,
            Some(InitialPublicationBind {
                seed: SEED,
                publication: PUBLICATION,
                evidence: None,
                nonce: None,
            }),
            NOW,
        )
        .await;
    assert!(clock.committed.load(Ordering::SeqCst));
    assert!(matches!(result, Err(Error::Reconcile)));
    // Do not roll the clock back or revive the expired session. Obtain genuine
    // UV again at a later time, then read the original immutable stored winner.
    let later = session.expires + 1;
    clock.now.store(later, Ordering::SeqCst);
    let fresh = original_login(&mut service, &mut f.member, later).await;
    let receipt = service
        .initial_creation(&fresh.token, None, later)
        .await
        .unwrap();
    assert_eq!(receipt.seed, SEED);
    assert_eq!(receipt.publication, Some(PUBLICATION));
    assert_eq!(receipt.checked_at, later);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_bind_waiting_for_the_original_member_lease_leaves_no_publication() {
    let f = routes::fixture().await;
    let service = f.service.door.community_backend().unwrap().lock().await;
    let (grant, authentication) = service
        .authenticate_current(&f.member.session, NOW)
        .await
        .unwrap();
    let lease = service
        .facade
        .membership()
        .initial_creation(&authentication, grant.expires.try_into().unwrap())
        .await
        .unwrap();
    // The actual owner lease serializes auth/metadata. Cancellation here cannot
    // race a write, and dropping it must permit a later fresh owner operation.
    let bind = service.initial_creation(
        &f.member.session,
        Some(InitialPublicationBind {
            seed: SEED,
            publication: PUBLICATION,
            evidence: None,
            nonce: None,
        }),
        NOW,
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), bind)
            .await
            .is_err()
    );
    drop(lease);
    let state = service
        .initial_creation(&f.member.session, None, NOW)
        .await
        .unwrap();
    assert_eq!(state.seed, SEED);
    assert_eq!(state.publication, None);
    // A passkey session never carries genesis stamp evidence.
    assert!(matches!(
        service
            .initial_creation(
                &f.member.session,
                Some(InitialPublicationBind {
                    seed: SEED,
                    publication: PUBLICATION,
                    evidence: Some(vec![1]),
                    nonce: None,
                }),
                NOW,
            )
            .await,
        Err(Error::Invalid)
    ));
    let bound = service
        .initial_creation(
            &f.member.session,
            Some(InitialPublicationBind {
                seed: SEED,
                publication: PUBLICATION,
                evidence: None,
                nonce: None,
            }),
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(bound.publication, Some(PUBLICATION));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaf_completion_floor_withholds_lost_bind_reply_but_exact_receipt_recovers() {
    let f = routes::fixture().await;
    let mut service = f.service.door.community_backend().unwrap().lock().await;
    // The real Membership clock advances, while the host rolls below that
    // observation. Genuine auth/key/lifecycle checks and metadata CAS still run.
    f.service.clock.set(NOW + 20);
    service.clock = Arc::new(FixedClock(NOW));
    let result = service
        .initial_creation(
            &f.member.session,
            Some(InitialPublicationBind {
                seed: SEED,
                publication: PUBLICATION,
                evidence: None,
                nonce: None,
            }),
            NOW,
        )
        .await;
    assert!(matches!(result, Err(Error::Reconcile)));
    service.clock = f.service.clock.clone();
    let receipt = service
        .initial_creation(&f.member.session, None, NOW + 20)
        .await
        .unwrap();
    assert_eq!(receipt.seed, SEED);
    assert_eq!(receipt.publication, Some(PUBLICATION));
    assert_eq!(receipt.checked_at, NOW + 20);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_expiry_after_a_real_owner_wait_refuses_before_binding() {
    let mut f = routes::fixture().await;
    let service = f.service.door.community_backend().unwrap().lock().await;
    let (grant, authentication) = service
        .authenticate_current(&f.member.session, NOW)
        .await
        .unwrap();
    let lease = service
        .facade
        .membership()
        .initial_creation(&authentication, grant.expires.try_into().unwrap())
        .await
        .unwrap();
    {
        let bind = service.initial_creation(
            &f.member.session,
            Some(InitialPublicationBind {
                seed: SEED,
                publication: PUBLICATION,
                evidence: None,
                nonce: None,
            }),
            NOW,
        );
        tokio::pin!(bind);
        tokio::select! {
            value = &mut bind => panic!("member lease did not serialize initial binding: {}", value.is_ok()),
            _ = tokio::time::sleep(std::time::Duration::from_millis(25)) => {},
        }
        f.service.clock.set(grant.expires);
        drop(lease);
        // The wait is inside the leaf's creation-state acquisition. Its first
        // post-lock deadline check refuses before the durable Keyhole bind.
        let result = bind.await;
        assert!(
            matches!(result, Err(Error::Refused)),
            "expected the known pre-write refusal, got {:?}",
            result.err()
        );
    }
    drop(service);
    f.member.session = login(
        &f.service,
        HOST,
        &mut f.member.authenticator,
        &f.member.user,
        &f.member.credential,
    )
    .await;
    let receipt: InitialCreationResponse = serde_json::from_value(
        client(&f.service, HOST, Some(&f.member.session))
            .call("initial_creation", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt.publication, None);
}
