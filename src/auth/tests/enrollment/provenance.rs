//! Exact original-key reads, immutable CAS and retained unknown outcomes.
use super::*;
use crate::service::Clock;
use std::sync::atomic::AtomicBool;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_current_key_queries_and_equal_cas_retries_preserve_the_first_publication() {
    let (_dir, db) = database().await;
    let mut auth = auth(&db, None, 4);
    let clock = TestClock(AtomicU64::new(NOW));
    let session = seeded(&mut auth, &mut Resident::default()).await;
    for publication in [2, 2] {
        let state = auth
            .initial_creation(
                &session.token,
                Some(InitialPublicationBind {
                    seed: [1; 32],
                    publication: [publication; 32],
                    evidence: None,
                }),
                NOW,
                &clock,
            )
            .await
            .unwrap();
        assert_eq!(state.publication, Some([2; 32]));
    }
    for (seed, publication) in [(1, 3), (2, 2), (0, 2), (1, 0)] {
        assert!(matches!(
            auth.initial_creation(
                &session.token,
                Some(InitialPublicationBind {
                    seed: [seed; 32],
                    publication: [publication; 32],
                    evidence: None,
                }),
                NOW,
                &clock
            )
            .await,
            Err(Error::Refused)
        ));
    }
    let current = auth
        .initial_creation(&session.token, None, NOW, &clock)
        .await
        .unwrap();
    assert_eq!(current.publication, Some([2; 32]));
    auth.logout(&session.token);
    assert!(matches!(
        auth.initial_creation(&session.token, None, NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
}

struct CommitClock {
    keys: Arc<Passkeys<LibsqlStore>>,
    authentication: Arc<ckyh::Authentication>,
    observed: AtomicBool,
}
impl Clock for CommitClock {
    fn now(&self) -> u64 {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let state = self.keys.initial_creation(&self.authentication).unwrap();
                    if state.publication() == Some([2; 32]) {
                        self.observed.store(true, Ordering::SeqCst);
                        NOW + 600
                    } else {
                        NOW
                    }
                })
                .join()
                .unwrap()
        })
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_committed_publication_with_expired_reply_is_reconcile_and_fresh_uv_reads_winner() {
    let (_dir, db) = database().await;
    let mut auth = auth(&db, None, 4);
    let mut device = Resident::default();
    let session = seeded(&mut auth, &mut device).await;
    let clock = CommitClock {
        keys: auth.passkeys.clone(),
        authentication: auth.sessions[&session.token].authentication.clone(),
        observed: AtomicBool::new(false),
    };
    assert!(matches!(
        auth.initial_creation(
            &session.token,
            Some(InitialPublicationBind {
                seed: [1; 32],
                publication: [2; 32],
                evidence: None,
            }),
            NOW,
            &clock
        )
        .await,
        Err(Error::Reconcile)
    ));
    assert!(clock.observed.load(Ordering::SeqCst));
    let begin = auth.login_discoverable_begin(NOW + 601).await.unwrap();
    let mut credential = device.ceremony(begin.options, false, ORIGIN).await;
    strip_prf(&mut credential);
    let fresh = auth
        .login_finish(
            LoginFinish {
                ceremony: begin.ceremony,
                credential: serde_json::from_value(credential).unwrap(),
            },
            NOW + 601,
        )
        .await
        .unwrap();
    let state = auth
        .initial_creation(
            &fresh.token,
            None,
            NOW + 601,
            &TestClock(AtomicU64::new(NOW + 601)),
        )
        .await
        .unwrap();
    assert_eq!(state.seed, [1; 32]);
    assert_eq!(state.publication, Some([2; 32]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_added_same_user_key_cannot_read_or_bind_the_original_keys_creation() {
    let (_dir, db) = database().await;
    let mut auth = auth(&db, None, 4);
    let clock = TestClock(AtomicU64::new(NOW));
    let original = seeded(&mut auth, &mut Resident::default()).await;
    let AddedPasskey::Challenge {
        ceremony, options, ..
    } = auth
        .add_passkey(&original.token, AddPasskey::Begin, NOW)
        .await
        .unwrap()
    else {
        panic!("original addition challenge")
    };
    let mut added = Resident::default();
    let mut credential = added.ceremony(options, true, ORIGIN).await;
    strip_prf(&mut credential);
    auth.add_passkey(
        &original.token,
        AddPasskey::Finish {
            ceremony,
            credential: serde_json::from_value(credential).unwrap(),
        },
        NOW,
    )
    .await
    .unwrap();
    let request = login(&mut auth, &mut added).await;
    let other = auth.login_finish(request, NOW).await.unwrap();
    assert_eq!(original.user, other.user);
    assert_ne!(
        auth.sessions[&original.token].grant.credential,
        auth.sessions[&other.token].grant.credential
    );
    assert!(matches!(
        auth.initial_creation(&other.token, None, NOW, &clock).await,
        Err(Error::Refused)
    ));
    assert!(matches!(
        auth.initial_creation(
            &other.token,
            Some(InitialPublicationBind {
                seed: [1; 32],
                publication: [2; 32],
                evidence: None,
            }),
            NOW,
            &clock
        )
        .await,
        Err(Error::Refused)
    ));
    let current = auth
        .initial_creation(&original.token, None, NOW, &clock)
        .await
        .unwrap();
    assert_eq!(current.seed, [1; 32]);
    assert_eq!(current.publication, None);
    let keys = auth.passkeys.clone();
    let grant = auth.sessions[&original.token].grant.clone();
    tokio::task::spawn_blocking(move || keys.revoke(grant.user, &grant.credential))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        auth.initial_creation(&original.token, None, NOW, &clock)
            .await,
        Err(Error::Unauthorized)
    ));
}

struct RegistrationCommitClock {
    keys: Arc<Passkeys<LibsqlStore>>,
    user: Uuid,
    observed: AtomicBool,
}
impl Clock for RegistrationCommitClock {
    fn now(&self) -> u64 {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    if self.keys.list(self.user).unwrap().is_empty() {
                        NOW
                    } else {
                        self.observed.store(true, Ordering::SeqCst);
                        NOW + 300
                    }
                })
                .join()
                .unwrap()
        })
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_registration_with_lost_reply_preserves_seed_and_cannot_retry_the_ceremony() {
    let (_dir, db) = database().await;
    let mut auth = auth(&db, None, 4);
    let original = auth.register_begin(start(None), NOW).await.unwrap();
    let continued = auth
        .continue_initial_registration(
            continuation(&original.ceremony, 1),
            NOW,
            &TestClock(AtomicU64::new(NOW)),
        )
        .await
        .unwrap();
    let mut device = Resident::default();
    let finish = registration(&mut device, ceremony(continued)).await;
    let retry: RegisterFinish =
        serde_json::from_value(serde_json::to_value(&finish).unwrap()).unwrap();
    let clock = RegistrationCommitClock {
        keys: auth.passkeys.clone(),
        user: Uuid::parse_str(&original.user).unwrap(),
        observed: AtomicBool::new(false),
    };
    assert!(matches!(
        auth.register_finish_live(finish, NOW, &clock).await,
        Err(Error::Reconcile)
    ));
    assert!(clock.observed.load(Ordering::SeqCst));
    assert!(matches!(
        auth.register_finish_live(retry, NOW + 300, &clock).await,
        Err(Error::Unauthorized)
    ));
    let begin = auth.login_discoverable_begin(NOW + 301).await.unwrap();
    let mut credential = device.ceremony(begin.options, false, ORIGIN).await;
    strip_prf(&mut credential);
    let session = auth
        .login_finish(
            LoginFinish {
                ceremony: begin.ceremony,
                credential: serde_json::from_value(credential).unwrap(),
            },
            NOW + 301,
        )
        .await
        .unwrap();
    let state = auth
        .initial_creation(
            &session.token,
            None,
            NOW + 301,
            &TestClock(AtomicU64::new(NOW + 301)),
        )
        .await
        .unwrap();
    assert_eq!(session.user, original.user);
    assert_eq!(state.seed, [1; 32]);
    assert_eq!(state.publication, None);
}
