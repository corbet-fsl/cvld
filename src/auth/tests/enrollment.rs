//! Genuine first-key ownership, exact retries and committed-unknown outcomes.
use super::*;
use crate::test_support::TestClock;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "enrollment/provenance.rs"]
mod provenance;

fn continuation(ceremony: &str, seed: u8) -> GlobalInitialRegistrationContinue {
    GlobalInitialRegistrationContinue {
        ceremony: ceremony.into(),
        seed: [seed; 32],
    }
}
fn ceremony(initial: InitialCeremony) -> Ceremony {
    Ceremony {
        ceremony: initial.ceremony,
        user: initial.user,
        options: initial.options,
    }
}
async fn seeded(auth: &mut Auth, device: &mut Resident) -> Session {
    let original = auth.register_begin(start(None), NOW).await.unwrap();
    let continued = auth
        .continue_initial_registration(
            continuation(&original.ceremony, 1),
            NOW,
            &TestClock(AtomicU64::new(NOW)),
        )
        .await
        .unwrap();
    let finish = registration(device, ceremony(continued)).await;
    auth.register_finish(finish, NOW).await.unwrap();
    let request = login(auth, device).await;
    auth.login_finish(request, NOW).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continuation_retains_uuid_exact_challenge_deadline_and_one_seed() {
    let (_dir, db) = database().await;
    let mut auth = auth(&db, None, 4);
    let clock = TestClock(AtomicU64::new(NOW));
    let original = auth.register_begin(start(None), NOW).await.unwrap();
    let first = auth
        .continue_initial_registration(continuation(&original.ceremony, 1), NOW, &clock)
        .await
        .unwrap();
    assert_eq!(first.user, original.user);
    assert_eq!(first.ceremony, original.ceremony);
    assert_ne!(
        first.options["publicKey"]["challenge"],
        original.options["publicKey"]["challenge"]
    );
    assert_eq!(first.expires_at, NOW + 300);
    clock.0.store(NOW + 20, Ordering::SeqCst);
    let equal = auth
        .continue_initial_registration(continuation(&original.ceremony, 1), NOW, &clock)
        .await
        .unwrap();
    assert_eq!(equal.options, first.options);
    assert_eq!(equal.expires_at, first.expires_at);
    assert_eq!(equal.checked_at, NOW + 20);
    assert!(matches!(
        auth.continue_initial_registration(continuation(&original.ceremony, 2), NOW, &clock)
            .await,
        Err(Error::Refused)
    ));
    let mut device = Resident::default();
    let finish = registration(&mut device, ceremony(equal)).await;
    auth.register_finish_live(finish, NOW + 20, &clock)
        .await
        .unwrap();
    assert!(matches!(
        auth.continue_initial_registration(continuation(&original.ceremony, 1), NOW + 20, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
    let request = login(&mut auth, &mut device).await;
    let session = auth.login_finish(request, NOW + 20).await.unwrap();
    let state = auth
        .initial_creation(&session.token, None, NOW + 20, &clock)
        .await
        .unwrap();
    assert_eq!(state.seed, [1; 32]);
    assert_eq!(state.publication, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_and_continue_have_one_winner_and_legacy_keys_cannot_gain_a_seed() {
    let (_dir, db) = database().await;
    let mut auth = auth(&db, None, 4);
    let clock = TestClock(AtomicU64::new(NOW));
    // The original finish wins: provenance cannot be attached retrospectively.
    let original = auth.register_begin(start(None), NOW).await.unwrap();
    let id = original.ceremony.clone();
    let mut device = Resident::default();
    let finish = registration(&mut device, original).await;
    auth.register_finish(finish, NOW).await.unwrap();
    assert!(matches!(
        auth.continue_initial_registration(continuation(&id, 1), NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
    let request = login(&mut auth, &mut device).await;
    let session = auth.login_finish(request, NOW).await.unwrap();
    assert!(matches!(
        auth.initial_creation(
            &session.token,
            Some(InitialPublicationBind {
                seed: [1; 32],
                publication: [2; 32]
            }),
            NOW,
            &clock
        )
        .await,
        Err(Error::Refused)
    ));
    // The refreshed challenge wins: an old genuine response cannot finish it.
    let original = auth.register_begin(start(None), NOW).await.unwrap();
    let id = original.ceremony.clone();
    let user = Uuid::parse_str(&original.user).unwrap();
    let old = registration(&mut Resident::default(), original).await;
    auth.continue_initial_registration(continuation(&id, 1), NOW, &clock)
        .await
        .unwrap();
    assert!(matches!(
        auth.register_finish(old, NOW).await,
        Err(Error::Refused)
    ));
    let keys = auth.passkeys.clone();
    assert!(
        tokio::task::spawn_blocking(move || keys.list(user))
            .await
            .unwrap()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_ceremony_operator_zero_seed_clock_rollback_and_original_monotonic_expiry_refuse() {
    let (_dir, db) = database().await;
    let mut auth = auth(&db, None, 4);
    let clock = TestClock(AtomicU64::new(NOW));
    let original = auth.register_begin(start(None), NOW).await.unwrap();
    assert!(matches!(
        auth.continue_initial_registration(continuation("foreign", 1), NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        auth.continue_initial_registration(continuation(&original.ceremony, 0), NOW, &clock)
            .await,
        Err(Error::Invalid)
    ));
    clock.0.store(NOW + 20, Ordering::SeqCst);
    auth.continue_initial_registration(continuation(&original.ceremony, 1), NOW, &clock)
        .await
        .unwrap();
    clock.0.store(NOW + 15, Ordering::SeqCst);
    assert!(matches!(
        auth.continue_initial_registration(continuation(&original.ceremony, 1), NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
    clock.0.store(NOW + 20, Ordering::SeqCst);
    auth.registrations
        .get_mut(&original.ceremony)
        .unwrap()
        .deadline = std::time::Instant::now();
    assert!(matches!(
        auth.continue_initial_registration(continuation(&original.ceremony, 1), NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
    let mut operator = super::auth(&db, Some(Uuid::new_v4()), 4);
    let original = operator
        .register_begin(start(Some(BOOTSTRAP)), NOW)
        .await
        .unwrap();
    assert!(matches!(
        operator
            .continue_initial_registration(continuation(&original.ceremony, 1), NOW, &clock)
            .await,
        Err(Error::Forbidden)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_different_seed_still_retains_its_observed_clock_floor() {
    let (_dir, db) = database().await;
    let mut auth = auth(&db, None, 4);
    let clock = TestClock(AtomicU64::new(NOW));
    let original = auth.register_begin(start(None), NOW).await.unwrap();
    auth.continue_initial_registration(continuation(&original.ceremony, 1), NOW, &clock)
        .await
        .unwrap();
    clock.0.store(NOW + 20, Ordering::SeqCst);
    assert!(matches!(
        auth.continue_initial_registration(continuation(&original.ceremony, 2), NOW, &clock)
            .await,
        Err(Error::Refused)
    ));
    clock.0.store(NOW + 15, Ordering::SeqCst);
    assert!(matches!(
        auth.continue_initial_registration(continuation(&original.ceremony, 1), NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_real_challenge_preparation_retains_the_observed_pending_floor() {
    use std::{future::Future, task::Poll};
    let (_dir, db) = database().await;
    let mut auth = auth(&db, None, 4);
    let clock = TestClock(AtomicU64::new(NOW + 20));
    let original = auth.register_begin(start(None), NOW).await.unwrap();
    let owner_count = Arc::strong_count(&auth.passkeys);
    let mut preparing = Box::pin(auth.continue_initial_registration(
        continuation(&original.ceremony, 1),
        NOW,
        &clock,
    ));
    std::future::poll_fn(|cx| {
        // The sole runtime thread has not driven the queued real SDK/SQL work.
        assert!(matches!(preparing.as_mut().poll(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    drop(preparing);
    assert_eq!(auth.registrations[&original.ceremony].observed, NOW + 20);
    assert!(auth.registrations[&original.ceremony].initial.is_none());
    clock.0.store(NOW + 15, Ordering::SeqCst);
    assert!(matches!(
        auth.continue_initial_registration(continuation(&original.ceremony, 1), NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
    // The cancelled SDK worker may still perform its second real list. Wait
    // for its captured owner to be dropped before ending this sole runtime.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while Arc::strong_count(&auth.passkeys) > owner_count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let keys = auth.passkeys.clone();
    let user = Uuid::parse_str(&original.user).unwrap();
    assert!(
        tokio::task::spawn_blocking(move || keys.list(user))
            .await
            .unwrap()
            .unwrap()
            .is_empty()
    );
}
