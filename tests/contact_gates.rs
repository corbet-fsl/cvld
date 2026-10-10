//! Real libSQL budgets, leaf HTTP parsing, signed policies and blind passports.
//! Only external HTTP is inert; no vendor network or spending occurs.
#![cfg(feature = "server")]
use cfbk::cost;
use cgbl::{
    CheckId, FingerprintKey, GatePolicy, Global, GlobalGate, Limits, Mode, Policy, Subject,
    storage::MemoryStore,
};
use cpsd::{
    GateId, HolderSecret, KeyId,
    rand::{SeedableRng, rngs::StdRng},
};
use cvld::{
    contact_gates::{
        self, Amount, Channel, Constraints, ContactConfig, Contacts, Coverage, Error, Order,
        Outcome, Owner, ProviderConfig, Tariff,
        state::{Ledger, Reservation, SCHEMA},
    },
    service::Clock,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

const PHONE: &str = "+12025550123";
const MAILBOX: &str = "Member+alias@example.test";
const COHORT: u64 = 5 * 86400;
struct Time(AtomicU64);
impl Clock for Time {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
impl Time {
    fn new() -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(100)))
    }
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}
fn amount(atoms: u64) -> Amount {
    Amount {
        unit: "FIXTURE".into(),
        scale: 0,
        atoms,
    }
}
fn domain(atoms: u64) -> cost::Amount {
    cost::Amount {
        unit: cost::Unit {
            code: "FIXTURE".into(),
            scale: 0,
        },
        atoms,
    }
}
fn owner(name: &str) -> Owner {
    Owner {
        subject: Subject::new(name).unwrap(),
        session: [7; 32],
    }
}
fn check(seed: u64) -> CheckId {
    CheckId::generate(&mut StdRng::seed_from_u64(seed))
}
fn tariff(atoms: u64) -> Tariff {
    Tariff {
        coverage: Coverage::AllAcceptedRequests,
        maximum: amount(atoms),
        exact: false,
        source: "inert test cap; no vendor price claim".into(),
        scope: "all fixture operations, account/service/channel and failures".into(),
        valid_until: 200,
    }
}
fn config(directory: &std::path::Path, channels: &[Channel]) -> ContactConfig {
    let secret = directory.join("provider-secret");
    std::fs::write(&secret, b"private-inert-provider-secret").unwrap();
    let key = directory.join("stable-identity-key");
    std::fs::write(&key, [8; 32]).unwrap();
    ContactConfig {
        providers: channels
            .iter()
            .enumerate()
            .map(|(index, &channel)| ProviderConfig {
                id: format!("option-{index}"),
                provider: "twilio".into(),
                account: format!("AC{}", "0".repeat(32)),
                service: format!("VA{}", "0".repeat(32)),
                credential_file: secret.to_str().unwrap().into(),
                channel,
                begin: tariff(4 + index as u64),
                check: tariff(3),
            })
            .collect(),
        phone_identity_key_file: Some(key.to_str().unwrap().into()),
        mailbox_identity_key_file: Some(key.to_str().unwrap().into()),
        capacity: 10,
        ceremony_seconds: 90,
        budget: amount(20),
        max_attempts: 3,
        transport_timeout_seconds: 5,
    }
}
async fn db(path: &std::path::Path) -> crlt::Db {
    let database = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
        .await
        .unwrap();
    database
        .migrate(&[
            crlt::Migration::new(1, "contact-operations", SCHEMA),
            crlt::Migration::new(2, "comparison-keys", contact_gates::state::BINDING_SCHEMA),
            crlt::Migration::new(3, "global-domain", cgbl::storage::SCHEMA),
        ])
        .await
        .unwrap();
    database
}
type Facade<S = MemoryStore> = Global<S, csgn::MemoryStore, cpsd::MemoryStore>;
async fn facade() -> Facade {
    facade_with_store(MemoryStore::new("global").unwrap()).await
}
async fn facade_with_store<S: cgbl::storage::Store>(store: S) -> Facade<S> {
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "cgbl:global",
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * 86400,
    )
    .await
    .unwrap();
    let issuer = cpsd::IssuerKey::generate(
        &mut StdRng::seed_from_u64(1),
        KeyId::new("contacts").unwrap(),
        ["cphn", "cmbx"].map(|g| GateId::new(g).unwrap()).to_vec(),
    )
    .unwrap();
    let mut facade = Global::open(
        store,
        cpsd::MemoryStore::new(cpsd::CommunityId::new(b"global").unwrap(), 10).unwrap(),
        issuer,
        signer,
        FingerprintKey::from_bytes(&mut [9; 32]),
        Mode::Production,
        Limits {
            challenge_ttl: 60,
            pending_capacity: 10,
        },
    )
    .await
    .unwrap();
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "policy-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        0,
        30 * 86400,
    )
    .await
    .unwrap();
    let policy = Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: COHORT,
        gates: ["cphn", "cmbx"]
            .map(|g| GatePolicy {
                gate: g.into(),
                provider: "twilio".into(),
                uniqueness: true,
            })
            .to_vec(),
    };
    let signed = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            0,
            COHORT + 86400,
        )
        .await
        .unwrap();
    facade
        .install_policy(&signed, authority.key_ring().unwrap(), 100)
        .await
        .unwrap();
    facade
}

#[derive(Clone, Copy)]
enum Reply {
    Normal,
    NotSent,
    Ambiguous,
    Malformed,
    Refused,
    Block,
}
#[derive(Clone)]
struct Fixture(Arc<Wire>);
impl std::ops::Deref for Fixture {
    type Target = Wire;
    fn deref(&self) -> &Wire {
        &self.0
    }
}
struct Wire {
    replies: Mutex<VecDeque<Reply>>,
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
impl Wire {
    fn new(replies: impl IntoIterator<Item = Reply>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into_iter().collect()),
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        })
    }
}
macro_rules! wire {
    ($leaf:ident, $destination:expr, $channel:expr) => {
        impl $leaf::Transport for Fixture {
            fn mode(&self) -> cost::Mode { cost::Mode::Production }
            async fn send(&self, request: axum::http::Request<$leaf::Private>) -> std::result::Result<axum::http::Response<$leaf::Private>, $leaf::Error> {
                assert!(request.extensions().get::<$leaf::DispatchDeadline>().unwrap().valid_until > 100);
                assert!(request.headers()[axum::http::header::AUTHORIZATION].is_sensitive());
                self.calls.fetch_add(1, Ordering::SeqCst);
                let reply = self.replies.lock().unwrap().pop_front().unwrap_or(Reply::Normal);
                match reply {
                    Reply::NotSent => return Err($leaf::Error::NotDispatched),
                    Reply::Ambiguous => return Err($leaf::Error::Uncertain),
                    Reply::Malformed => return Ok(axum::http::Response::new($leaf::Private::new(b"private-malformed-provider-body".to_vec()))),
                    Reply::Block => { self.entered.notify_one(); self.resume.notified().await; },
                    _ => (),
                }
                let checking = request.uri().path().ends_with("/VerificationCheck");
                let request_body = std::str::from_utf8(request.body().expose()).unwrap();
                let channel = if request_body.contains("Channel=call") { "call" } else if request_body.contains("Channel=whatsapp") { "whatsapp" } else { $channel };
                let mut response = axum::http::Response::new($leaf::Private::new(serde_json::to_vec(&serde_json::json!({ "sid": format!("VE{}", "0".repeat(32)), "account_sid": format!("AC{}", "0".repeat(32)), "service_sid": format!("VA{}", "0".repeat(32)), "to": $destination, "channel": channel, "status": if checking { "approved" } else { "pending" }, "valid": checking, "extension": "private-upstream-extension" })).unwrap()));
                if matches!(reply, Reply::Refused) { *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS; }
                Ok(response)
            }
        }
    }
}
wire!(cphn, PHONE, "sms");
wire!(cmbx, MAILBOX, "email");

fn selections<S: cgbl::storage::Store>(
    facade: &Facade<S>,
    owner: &Owner,
    check: &CheckId,
    channels: &[Channel],
) -> Vec<(String, cgbl::contacts::ContactBinding)> {
    channels
        .iter()
        .enumerate()
        .map(|(index, channel)| {
            (
                format!("option-{index}"),
                facade
                    .contact_binding(channel.gate(), "twilio", &owner.subject, check)
                    .unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn production_contacts_reach_a_real_passport_and_persist_only_opaque_operations() {
    let dir = tempfile::tempdir().unwrap();
    let db = db(&dir.path().join("contacts.db")).await;
    let clock = Time::new();
    let facade = facade().await;
    let wire = Wire::new([]);
    let cfg = config(dir.path(), &[Channel::Sms, Channel::Email]);
    let mut contacts = Contacts::with_transport(&db, "global", &cfg, clock, Fixture(wire.clone()))
        .await
        .unwrap();
    let alice = owner("alice");
    for (index, channel, destination) in [(0, Channel::Sms, PHONE), (1, Channel::Email, MAILBOX)] {
        let check = check(index as u64 + 1);
        let binding = facade
            .contact_binding(channel.gate(), "twilio", &alice.subject, &check)
            .unwrap();
        let preview = contacts
            .prepare_begin(
                alice.clone(),
                vec![(format!("option-{index}"), binding)],
                destination,
                Constraints {
                    check: check.clone(),
                    budget: amount(10),
                    max_attempts: 3,
                    order: Order::Configured,
                    pending_expires_at: 190,
                    fact_expires_at: COHORT + 1,
                },
            )
            .unwrap();
        assert_eq!(wire.calls.load(Ordering::SeqCst), index * 2);
        let pending = contacts
            .execute(&preview.operation, &preview.authorization, &alice)
            .await
            .unwrap();
        assert_eq!(pending.outcome, Outcome::Pending);
        assert_eq!(pending.exposure.atoms, 4 + index as u64);
        // Wrong-phase repeated dispatch must preserve the pending session.
        assert!(matches!(
            contacts
                .execute(&preview.operation, &preview.authorization, &alice)
                .await,
            Err(Error::Conflict)
        ));
        let finish = contacts
            .prepare_check(&preview.operation, &alice, "123456")
            .unwrap();
        assert_ne!(finish.authorization, preview.authorization);
        assert!(matches!(
            contacts
                .execute(&preview.operation, &preview.authorization, &alice)
                .await,
            Err(Error::Conflict)
        ));
        let verified = contacts
            .execute(&finish.operation, &finish.authorization, &alice)
            .await
            .unwrap();
        assert_eq!(verified.outcome, Outcome::Verified);
        assert_eq!(verified.exposure.atoms, 7 + index as u64);
        let gate = contacts.gate(&preview.operation, &alice).unwrap();
        assert!(!gate.development_only());
        for _ in 0..2 {
            assert_eq!(
                facade
                    .run_gate(gate, &alice.subject, gate.input(), 100, &check)
                    .await
                    .unwrap()
                    .valid_until,
                COHORT
            );
        }
        assert!(matches!(
            contacts.prepare_check(&preview.operation, &alice, "123456"),
            Err(Error::Conflict)
        ));
    }
    assert_eq!(wire.calls.load(Ordering::SeqCst), 4);
    let mut rng = StdRng::seed_from_u64(99);
    let session = cgbl::Session::authenticated(alice.subject.clone(), alice.session).unwrap();
    let challenge = facade
        .challenge(&mut rng, &session, 100, 150)
        .await
        .unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let (request, pending) =
        cpsd::request_issue(&mut rng, &secret, facade.issuer_public_key(), &challenge).unwrap();
    let blind = facade
        .issue(&mut rng, &session, &challenge, &request, 101)
        .await
        .unwrap();
    let passport = pending.finish(&blind).unwrap();
    let presentation_request = cpsd::PresentationRequest::for_epoch(
        &mut rng,
        cpsd::CommunityId::new(b"consumer").unwrap(),
        1,
        [GateId::new("cphn").unwrap(), GateId::new("cmbx").unwrap()],
        120,
        COHORT,
    )
    .unwrap();
    let mut consumer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "consumer",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        0,
        COHORT + 86400,
    )
    .await
    .unwrap();
    let signed = consumer
        .sign(
            csgn::Kind::Credential,
            &presentation_request.to_bytes(),
            0,
            121,
        )
        .await
        .unwrap();
    let authority = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        presentation_request.community().clone(),
        consumer.key_ring().unwrap().clone(),
    );
    let proof = passport
        .present(&mut rng, &authority, &signed, 120)
        .unwrap();
    assert_eq!(
        cpsd::verify(
            &mut rng,
            &[facade.issuer_public_key().clone()],
            &presentation_request,
            &proof
        )
        .unwrap(),
        secret.pseudonym(presentation_request.community())
    );
    let ledger = Ledger::new(&db, "global", Time::new()).unwrap();
    ledger.check_query_plans().await.unwrap();
    for table in ["cvld_contact_ceremony", "cvld_contact_dispatch"] {
        let rows = db
            .community("global")
            .unwrap()
            .query(&format!("SELECT * FROM {table}"), ())
            .await
            .unwrap();
        let diagnostic = format!("{rows:?}");
        for private in [
            PHONE,
            MAILBOX,
            "123456",
            "private-inert-provider-secret",
            "private-upstream-extension",
            "alice",
        ] {
            assert!(!diagnostic.contains(private));
        }
    }
}

#[tokio::test]
async fn cost_budget_covers_begin_and_check_and_subject_session_continuations_are_exact() {
    let dir = tempfile::tempdir().unwrap();
    let db = db(&dir.path().join("contacts.db")).await;
    let facade = facade().await;
    let wire = Wire::new([]);
    let clock = Time::new();
    let cfg = config(dir.path(), &[Channel::Sms]);
    let mut contacts =
        Contacts::with_transport(&db, "global", &cfg, clock.clone(), Fixture(wire.clone()))
            .await
            .unwrap();
    let alice = owner("alice");
    let operation = check(1);
    let preview = contacts
        .prepare_begin(
            alice.clone(),
            selections(&facade, &alice, &operation, &[Channel::Sms]),
            PHONE,
            Constraints {
                check: check(1),
                budget: amount(6),
                max_attempts: 3,
                order: Order::Configured,
                pending_expires_at: 190,
                fact_expires_at: COHORT + 1,
            },
        )
        .unwrap();
    let mut wrong_session = alice.clone();
    wrong_session.session = [8; 32];
    for who in [owner("bob"), wrong_session] {
        assert!(matches!(
            contacts
                .execute(&preview.operation, &preview.authorization, &who)
                .await,
            Err(Error::Conflict)
        ));
    }
    contacts
        .execute(&preview.operation, &preview.authorization, &alice)
        .await
        .unwrap();
    assert!(matches!(
        contacts.prepare_check(&preview.operation, &alice, "private-bad-code"),
        Err(Error::Input)
    ));
    let finish = contacts
        .prepare_check(&preview.operation, &alice, "123456")
        .unwrap();
    assert!(matches!(
        contacts
            .execute(&finish.operation, &finish.authorization, &alice)
            .await,
        Err(Error::Budget)
    ));
    assert_eq!(wire.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        contacts
            .status(&preview.operation, &alice)
            .await
            .unwrap()
            .exposure
            .atoms,
        4
    );
    assert!(contacts.gate(&preview.operation, &alice).is_err());
    clock.set(190);
    assert!(matches!(
        contacts.status(&preview.operation, &alice).await,
        Err(Error::Expired)
    ));
}

#[tokio::test]
async fn only_definitely_not_dispatched_attempts_allow_bounded_compatible_fallback() {
    for (first, expected, calls) in [
        (Reply::NotSent, Outcome::Pending, 2),
        (Reply::Ambiguous, Outcome::Uncertain, 1),
        (Reply::Malformed, Outcome::Uncertain, 1),
        (Reply::Refused, Outcome::Uncertain, 1),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let db = db(&dir.path().join("contacts.db")).await;
        let facade = facade().await;
        let wire = Wire::new([first]);
        let cfg = config(dir.path(), &[Channel::Sms, Channel::Call]);
        let alice = owner("alice");
        let mut contacts =
            Contacts::with_transport(&db, "global", &cfg, Time::new(), Fixture(wire.clone()))
                .await
                .unwrap();
        let preview = contacts
            .prepare_begin(
                alice.clone(),
                selections(&facade, &alice, &check(1), &[Channel::Sms, Channel::Call]),
                PHONE,
                Constraints {
                    check: check(1),
                    budget: amount(20),
                    max_attempts: 3,
                    order: Order::Configured,
                    pending_expires_at: 190,
                    fact_expires_at: COHORT + 1,
                },
            )
            .unwrap();
        let receipt = contacts
            .execute(&preview.operation, &preview.authorization, &alice)
            .await
            .unwrap();
        assert_eq!(receipt.outcome, expected);
        assert_eq!(wire.calls.load(Ordering::SeqCst), calls);
        assert_eq!(receipt.exposure.atoms, if calls == 2 { 9 } else { 4 });
    }
}

#[tokio::test]
async fn canceled_dispatch_retains_uncertainty_and_cannot_be_replayed_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("contacts.db");
    let database = db(&path).await;
    let facade = facade().await;
    let wire = Wire::new([Reply::Block]);
    let cfg = config(dir.path(), &[Channel::Sms]);
    let alice = owner("alice");
    let mut contacts = Contacts::with_transport(
        &database,
        "global",
        &cfg,
        Time::new(),
        Fixture(wire.clone()),
    )
    .await
    .unwrap();
    let preview = contacts
        .prepare_begin(
            alice.clone(),
            selections(&facade, &alice, &check(1), &[Channel::Sms]),
            PHONE,
            Constraints {
                check: check(1),
                budget: amount(10),
                max_attempts: 3,
                order: Order::Configured,
                pending_expires_at: 190,
                fact_expires_at: COHORT + 1,
            },
        )
        .unwrap();
    {
        let dispatch = contacts.execute(&preview.operation, &preview.authorization, &alice);
        tokio::pin!(dispatch);
        tokio::select! { result = &mut dispatch => panic!("blocked fixture completed: {result:?}"), _ = wire.entered.notified() => () }
    }
    assert_eq!(
        contacts
            .status(&preview.operation, &alice)
            .await
            .unwrap()
            .outcome,
        Outcome::Uncertain
    );
    assert!(matches!(
        contacts
            .execute(&preview.operation, &preview.authorization, &alice)
            .await,
        Err(Error::Conflict)
    ));
    let rows = database
        .community("global")
        .unwrap()
        .query(
            "SELECT operation, ceremony, binding, outcome FROM cvld_contact_dispatch",
            (),
        )
        .await
        .unwrap();
    assert_eq!(rows[0].get_str(3).unwrap(), "uncertain");
    let blob = |index| {
        let crlt::Value::Blob(value) = rows[0].get_value(index).unwrap() else {
            panic!("opaque ledger value must be a blob")
        };
        <[u8; 32]>::try_from(value.as_slice()).unwrap()
    };
    let operation = blob(0);
    let ceremony = blob(1);
    let binding = rows[0].get_str(2).unwrap().to_owned();
    drop(rows);
    drop(contacts);
    drop(database);
    let reopened = db(&path).await;
    let ledger = Ledger::new(&reopened, "global", Time::new()).unwrap();
    assert!(matches!(
        ledger
            .reserve(Reservation {
                ceremony,
                leaf_binding: [0; 32],
                operation,
                binding,
                maximum: domain(4),
                budget: amount(10),
                max_attempts: 3,
                ceremony_deadline: 190,
                dispatch_deadline: 190
            })
            .await,
        Err(Error::Conflict)
    ));
    assert_eq!(ledger.exposure(&ceremony).await.unwrap().atoms, 4);
    assert_eq!(wire.calls.load(Ordering::SeqCst), 1);
}

fn reservation(ceremony: u8, operation: u8) -> Reservation {
    Reservation {
        ceremony: [ceremony; 32],
        leaf_binding: [9; 32],
        operation: [operation; 32],
        binding: format!("opaque-{operation}"),
        maximum: domain(4),
        budget: amount(6),
        max_attempts: 3,
        ceremony_deadline: 190,
        dispatch_deadline: 180,
    }
}

#[tokio::test]
async fn durable_atomic_budget_dedup_and_single_use_leaf_seal_survive_contention() {
    let dir = tempfile::tempdir().unwrap();
    let database = db(&dir.path().join("contacts.db")).await;
    let clock = Time::new();
    let ledger = Ledger::new(&database, "global", clock.clone()).unwrap();
    let (first, second) = tokio::join!(
        ledger.reserve(reservation(1, 1)),
        ledger.reserve(reservation(1, 2))
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(ledger.exposure(&[1; 32]).await.unwrap().atoms, 4);
    let mut changed = reservation(1, 3);
    changed.budget = amount(100);
    assert!(matches!(
        ledger.reserve(changed).await,
        Err(Error::Conflict)
    ));
    let seal = ledger.reserve(reservation(2, 3)).await.unwrap();
    assert!(
        cphn::DispatchState::reserve(&seal, &[9; 32], &[3; 32], "wrong", &domain(4), 180).is_err()
    );
    cphn::DispatchState::reserve(&seal, &[9; 32], &[3; 32], "opaque-3", &domain(4), 180).unwrap();
    assert!(
        cmbx::DispatchState::reserve(&seal, &[9; 32], &[3; 32], "opaque-3", &domain(4), 180)
            .is_err()
    );
    let seal = ledger.reserve(reservation(3, 4)).await.unwrap();
    clock.set(180);
    assert!(
        cphn::DispatchState::reserve(&seal, &[9; 32], &[4; 32], "opaque-4", &domain(4), 180)
            .is_err()
    );
    assert_eq!(ledger.exposure(&[3; 32]).await.unwrap().atoms, 4);
}

#[test]
fn local_simulation_uses_real_planning_and_cannot_construct_a_gate() {
    let offers = vec![
        cphn::SimulationOffer {
            channel: cphn::Channel::Sms,
            price: cost::Price::AtMost(domain(4)),
            source: "hypothetical-fixture".into(),
            valid_until: 200,
            outcome: cost::Outcome::SafeFailure,
        },
        cphn::SimulationOffer {
            channel: cphn::Channel::Call,
            price: cost::Price::AtMost(domain(3)),
            source: "hypothetical-fixture".into(),
            valid_until: 200,
            outcome: cost::Outcome::Success,
        },
    ];
    let simulated = contact_gates::simulate_phone(
        PHONE,
        b"explicit-fixture-scope",
        offers,
        cphn::SimulationSettings {
            order: cost::CostOrder::Configured,
            budget: domain(10),
            max_attempts: 2,
            now: 100,
        },
    )
    .unwrap();
    assert_eq!(simulated.attempts, 2);
    assert_eq!(simulated.exposure.atoms, 7);
    assert_eq!(simulated.outcome, cost::Outcome::Success);
    let mailbox = contact_gates::simulate_mailbox(
        MAILBOX,
        b"explicit-fixture-scope",
        vec![cmbx::SimulationOffer {
            channel: cmbx::Channel::Email,
            price: cost::Price::AtMost(domain(3)),
            source: "hypothetical-fixture".into(),
            valid_until: 200,
            outcome: cost::Outcome::Pending,
        }],
        cmbx::SimulationSettings {
            order: cost::CostOrder::Configured,
            budget: domain(10),
            max_attempts: 1,
            now: 100,
        },
    )
    .unwrap();
    assert_eq!(mailbox.outcome, cost::Outcome::Pending);
}

#[tokio::test]
async fn trusted_http_transport_refuses_missing_expired_or_foreign_routes_without_network() {
    use cvld::contact_gates::transport::HttpTransport;
    let clock = Time::new();
    let transport = HttpTransport::new(clock.clone(), 5).unwrap();
    assert!(matches!(
        HttpTransport::new(clock.clone(), 0),
        Err(Error::Configuration)
    ));
    for uri in [
        "https://forbidden.invalid/v2/Services/VA00000000000000000000000000000000/Verifications",
        "http://verify.twilio.com/v2/Services/VA00000000000000000000000000000000/Verifications",
        "https://verify.twilio.com/v2/Services/invalid/Verifications",
        "https://verify.twilio.com/v2/Services/VA00000000000000000000000000000000/Verifications?private=forbidden",
    ] {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .body(cphn::Private::new(vec![]))
            .unwrap();
        request
            .extensions_mut()
            .insert(cphn::DispatchDeadline { valid_until: 200 });
        assert!(matches!(
            cphn::Transport::send(&transport, request).await,
            Err(cphn::Error::NotDispatched)
        ));
    }
    let uri =
        "https://verify.twilio.com/v2/Services/VA00000000000000000000000000000000/Verifications";
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .body(cphn::Private::new(vec![]))
        .unwrap();
    assert!(matches!(
        cphn::Transport::send(&transport, request).await,
        Err(cphn::Error::NotDispatched)
    ));
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .body(cmbx::Private::new(vec![]))
        .unwrap();
    request
        .extensions_mut()
        .insert(cmbx::DispatchDeadline { valid_until: 100 });
    assert!(matches!(
        cmbx::Transport::send(&transport, request).await,
        Err(cmbx::Error::NotDispatched)
    ));
}

#[tokio::test]
async fn quote_expiry_clock_rollback_and_mixed_capabilities_refuse_before_http() {
    let dir = tempfile::tempdir().unwrap();
    let database = db(&dir.path().join("contacts.db")).await;
    let facade = facade().await;
    let clock = Time::new();
    let wire = Wire::new([]);
    let mut cfg = config(dir.path(), &[Channel::Sms, Channel::Email]);
    let alice = owner("alice");
    let mut contacts = Contacts::with_transport(
        &database,
        "global",
        &cfg,
        clock.clone(),
        Fixture(wire.clone()),
    )
    .await
    .unwrap();
    let constraints = || Constraints {
        check: check(1),
        budget: amount(20),
        max_attempts: 3,
        order: Order::Cheapest,
        pending_expires_at: 210,
        fact_expires_at: COHORT + 1,
    };
    assert!(matches!(
        contacts.prepare_begin(
            alice.clone(),
            selections(&facade, &alice, &check(1), &[Channel::Sms, Channel::Email]),
            PHONE,
            constraints()
        ),
        Err(Error::Configuration)
    ));
    let prepare = |contacts: &mut Contacts<Fixture>, seed| {
        contacts
            .prepare_begin(
                alice.clone(),
                vec![(
                    "option-0".into(),
                    facade
                        .contact_binding("cphn", "twilio", &alice.subject, &check(seed))
                        .unwrap(),
                )],
                PHONE,
                constraints(),
            )
            .unwrap()
    };
    let preview = prepare(&mut contacts, 2);
    clock.set(200);
    assert!(matches!(
        contacts
            .execute(&preview.operation, &preview.authorization, &alice)
            .await,
        Err(Error::Budget)
    ));
    assert_eq!(wire.calls.load(Ordering::SeqCst), 0);
    clock.set(100);
    let preview = prepare(&mut contacts, 3);
    clock.set(99);
    assert!(matches!(
        contacts
            .execute(&preview.operation, &preview.authorization, &alice)
            .await,
        Err(Error::Expired)
    ));
    assert_eq!(wire.calls.load(Ordering::SeqCst), 0);
    clock.set(100);
    cfg.providers[0].begin.source.clear();
    assert!(matches!(
        Contacts::with_transport(
            &database,
            "global",
            &cfg,
            clock.clone(),
            Fixture(wire.clone())
        )
        .await,
        Err(Error::Configuration)
    ));
    cfg.providers[0].begin = tariff(4);
    cfg.providers[0].begin.valid_until = 100;
    assert!(matches!(
        Contacts::with_transport(&database, "global", &cfg, clock, Fixture(wire)).await,
        Err(Error::Configuration)
    ));
}

#[tokio::test]
async fn real_contact_identity_remains_unique_across_authenticated_subjects() {
    let dir = tempfile::tempdir().unwrap();
    let database = db(&dir.path().join("contacts.db")).await;
    let facade = facade().await;
    let cfg = config(dir.path(), &[Channel::Sms, Channel::Email]);
    let wire = Wire::new([]);
    let mut contacts = Contacts::with_transport(
        &database,
        "global",
        &cfg,
        Time::new(),
        Fixture(wire.clone()),
    )
    .await
    .unwrap();
    for (member, name) in ["alice", "bob"].into_iter().enumerate() {
        let owner = owner(name);
        for (option, gate, destination) in [(0, "cphn", PHONE), (1, "cmbx", MAILBOX)] {
            let check = check((member * 10 + option + 1) as u64);
            let binding = facade
                .contact_binding(gate, "twilio", &owner.subject, &check)
                .unwrap();
            let preview = contacts
                .prepare_begin(
                    owner.clone(),
                    vec![(format!("option-{option}"), binding)],
                    destination,
                    Constraints {
                        check: check.clone(),
                        budget: amount(20),
                        max_attempts: 3,
                        order: Order::Configured,
                        pending_expires_at: 190,
                        fact_expires_at: COHORT + 1,
                    },
                )
                .unwrap();
            contacts
                .execute(&preview.operation, &preview.authorization, &owner)
                .await
                .unwrap();
            let finish = contacts
                .prepare_check(&preview.operation, &owner, "123456")
                .unwrap();
            contacts
                .execute(&finish.operation, &finish.authorization, &owner)
                .await
                .unwrap();
            let gate = contacts.gate(&preview.operation, &owner).unwrap();
            let result = facade
                .run_gate(gate, &owner.subject, gate.input(), 100, &check)
                .await;
            if member == 0 {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(cgbl::Error::Duplicate)));
            }
        }
    }
    assert_eq!(wire.calls.load(Ordering::SeqCst), 8);
}

#[tokio::test]
async fn expiry_while_waiting_for_the_database_does_not_dispatch_or_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let database = db(&dir.path().join("contacts.db")).await;
    let clock = Time::new();
    let ledger = Ledger::new(&database, "global", clock.clone()).unwrap();
    let held = database.tx("global").await.unwrap();
    let reserve = ledger.reserve(reservation(4, 5));
    tokio::pin!(reserve);
    tokio::select! { result = &mut reserve => assert!(result.is_err(), "the held connection should block reservation"), _ = tokio::task::yield_now() => () }
    clock.set(180);
    drop(held);
    assert!(matches!(reserve.await, Err(Error::Expired)));
    let rows = database
        .community("global")
        .unwrap()
        .query("SELECT operation FROM cvld_contact_dispatch", ())
        .await
        .unwrap();
    assert!(rows.is_empty());
}

async fn revised_policy<S: cgbl::storage::Store>(
    facade: &Facade<S>,
    phone_enabled: bool,
    phone_unique: bool,
) {
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "policy-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        0,
        30 * 86400,
    )
    .await
    .unwrap();
    let policy = Policy {
        version: 1,
        scope: "global".into(),
        revision: 2,
        epoch: 2,
        shared_expiry: COHORT,
        gates: vec![
            GatePolicy {
                gate: "cphn".into(),
                provider: if phone_enabled { "twilio" } else { "disabled" }.into(),
                uniqueness: phone_unique,
            },
            GatePolicy {
                gate: "cmbx".into(),
                provider: "twilio".into(),
                uniqueness: true,
            },
        ],
    };
    let signed = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            0,
            COHORT + 86400,
        )
        .await
        .unwrap();
    facade
        .install_policy(&signed, authority.key_ring().unwrap(), 100)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_real_subject_or_signed_policy_change_after_reservation_blocks_all_provider_http() {
    for cause in ["suspension", "policy"] {
        let directory = tempfile::tempdir().unwrap();
        let database = db(&directory.path().join("contacts.db")).await;
        let facade = facade().await;
        let wire = Wire::new([]);
        let clock = Time::new();
        let cfg = config(directory.path(), &[Channel::Sms]);
        let owner = owner("alice");
        let check = check(1);
        let mut contacts = Contacts::with_transport(
            &database,
            "global",
            &cfg,
            clock.clone(),
            Fixture(wire.clone()),
        )
        .await
        .unwrap();
        let preview = contacts
            .prepare_begin(
                owner.clone(),
                selections(&facade, &owner, &check, &[Channel::Sms]),
                PHONE,
                Constraints {
                    check: check.clone(),
                    budget: amount(10),
                    max_attempts: 3,
                    order: Order::Configured,
                    pending_expires_at: 190,
                    fact_expires_at: COHORT + 1,
                },
            )
            .unwrap();
        let calls = AtomicUsize::new(0);
        let verify = || -> std::pin::Pin<Box<dyn std::future::Future<Output=contact_gates::Result<u64>> + Send + '_>> {
            Box::pin(async {
                if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                    // The genuine persistent ledger now contains the maximum.
                    let rows = database.community("global").unwrap().query("SELECT exposure FROM cvld_contact_ceremony", ()).await.unwrap();
                    assert_eq!(rows[0].get_i64(0).unwrap(), 4);
                    if cause == "suspension" { facade.suspend(&owner.subject, cgbl::Suspension::Permanent(cgbl::PermanentReason::SelfBan), 100).await.unwrap(); } else { revised_policy(&facade, false, true).await; }
                }
                facade.authorize_contact("cphn", "twilio", &owner.subject, &check, &||clock.now()).await.map(|authorized| authorized.observed_at()).map_err(|_| Error::Refused)
            })
        };
        assert!(
            matches!(
                contacts
                    .execute_checked(&preview.operation, &preview.authorization, &owner, &verify)
                    .await,
                Err(Error::Uncertain)
            ),
            "{cause}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(wire.calls.load(Ordering::SeqCst), 0);
        let receipt = contacts.status(&preview.operation, &owner).await.unwrap();
        assert_eq!(receipt.outcome, Outcome::Uncertain);
        assert_eq!(receipt.exposure.atoms, 4);
        assert!(matches!(
            contacts
                .execute_checked(&preview.operation, &preview.authorization, &owner, &verify)
                .await,
            Err(Error::Conflict)
        ));
    }
}

#[tokio::test]
async fn comparison_keys_are_stable_on_reopen_and_provider_credentials_remain_replaceable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("contacts.db");
    let database = db(&path).await;
    let cfg = config(directory.path(), &[Channel::Sms, Channel::Email]);
    let contacts = Contacts::with_transport(
        &database,
        "global",
        &cfg,
        Time::new(),
        Fixture(Wire::new([])),
    )
    .await
    .unwrap();
    drop(contacts);
    drop(database);
    let database = db(&path).await;
    std::fs::write(
        &cfg.providers[0].credential_file,
        b"replacement-inert-provider-token",
    )
    .unwrap();
    let contacts = Contacts::with_transport(
        &database,
        "global",
        &cfg,
        Time::new(),
        Fixture(Wire::new([])),
    )
    .await
    .unwrap();
    drop(contacts);
    let before = database
        .community("global")
        .unwrap()
        .query(
            "SELECT domain, scope, commitment FROM cvld_contact_key_binding",
            (),
        )
        .await
        .unwrap();
    assert_eq!(before.len(), 2);
    let before: Vec<_> = before
        .iter()
        .map(|row| {
            (
                row.get_str(0).unwrap().to_owned(),
                row.get_str(1).unwrap().to_owned(),
                row.get_str(2).unwrap().to_owned(),
            )
        })
        .collect();
    std::fs::write(cfg.phone_identity_key_file.as_ref().unwrap(), [9; 32]).unwrap();
    assert!(matches!(
        Contacts::with_transport(
            &database,
            "global",
            &cfg,
            Time::new(),
            Fixture(Wire::new([]))
        )
        .await,
        Err(Error::Configuration)
    ));
    let after = database
        .community("global")
        .unwrap()
        .query(
            "SELECT domain, scope, commitment FROM cvld_contact_key_binding",
            (),
        )
        .await
        .unwrap();
    let after: Vec<_> = after
        .iter()
        .map(|row| {
            (
                row.get_str(0).unwrap().to_owned(),
                row.get_str(1).unwrap().to_owned(),
                row.get_str(2).unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(before, after);
    let mut copy = [8; 32];
    let commitment = cgbl::contacts::comparison_key_binding(
        "other",
        cgbl::contacts::ContactDomain::Phone,
        &mut copy,
    )
    .unwrap();
    assert!(matches!(
        Ledger::new(&database, "global", Time::new())
            .unwrap()
            .bind_comparison_keys(
                "other",
                &[contact_gates::state::ComparisonBinding {
                    domain: cgbl::contacts::ContactDomain::Phone,
                    commitment
                }]
            )
            .await,
        Err(Error::Configuration)
    ));
}

#[test]
fn configured_costs_require_explicit_coverage_of_every_accepted_request() {
    let valid = serde_json::to_value(tariff(4)).unwrap();
    assert!(serde_json::from_value::<Tariff>(valid.clone()).is_ok());
    let mut absent = valid.clone();
    absent.as_object_mut().unwrap().remove("coverage");
    assert!(serde_json::from_value::<Tariff>(absent).is_err());
    let mut partial = valid;
    partial["coverage"] = serde_json::json!("only_some_destinations");
    assert!(serde_json::from_value::<Tariff>(partial).is_err());
}

#[tokio::test]
async fn comparison_key_install_is_atomic_across_both_domains_under_contention() {
    use cgbl::contacts::{ContactDomain, comparison_key_binding};
    let directory = tempfile::tempdir().unwrap();
    let database = db(&directory.path().join("contacts.db")).await;
    let ledger = Ledger::new(&database, "global", Time::new()).unwrap();
    let bindings = |seed| {
        [ContactDomain::Phone, ContactDomain::Mailbox].map(|domain| {
            let mut key = [seed; 32];
            contact_gates::state::ComparisonBinding {
                domain,
                commitment: comparison_key_binding("global", domain, &mut key).unwrap(),
            }
        })
    };
    let first = bindings(8);
    let different = bindings(9);
    let (a, b) = tokio::join!(
        ledger.bind_comparison_keys("global", &first),
        ledger.bind_comparison_keys("global", &different)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let rows = database
        .community("global")
        .unwrap()
        .query(
            "SELECT domain, commitment FROM cvld_contact_key_binding",
            (),
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let winner = if a.is_ok() { &first } else { &different };
    for row in rows {
        let expected = winner
            .iter()
            .find(|binding| binding.domain.as_str() == row.get_str(0).unwrap())
            .unwrap();
        assert_eq!(row.get_str(1).unwrap(), expected.commitment);
    }
}

#[tokio::test]
async fn populated_legacy_phone_state_without_a_key_commitment_requires_explicit_migration() {
    for unique in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let database = db(&directory.path().join("contacts.db")).await;
        let facade =
            facade_with_store(cgbl::storage::LibsqlStore::new(&database, "global").unwrap()).await;
        if !unique {
            revised_policy(&facade, true, false).await;
        }
        let cfg = config(directory.path(), &[Channel::Sms]);
        let owner = owner("alice");
        let check = check(1);
        let mut contacts = Contacts::with_transport(
            &database,
            "global",
            &cfg,
            Time::new(),
            Fixture(Wire::new([])),
        )
        .await
        .unwrap();
        let preview = contacts
            .prepare_begin(
                owner.clone(),
                selections(&facade, &owner, &check, &[Channel::Sms]),
                PHONE,
                Constraints {
                    check: check.clone(),
                    budget: amount(10),
                    max_attempts: 3,
                    order: Order::Configured,
                    pending_expires_at: 190,
                    fact_expires_at: COHORT + 1,
                },
            )
            .unwrap();
        contacts
            .execute(&preview.operation, &preview.authorization, &owner)
            .await
            .unwrap();
        let finish = contacts
            .prepare_check(&preview.operation, &owner, "123456")
            .unwrap();
        contacts
            .execute(&finish.operation, &finish.authorization, &owner)
            .await
            .unwrap();
        let gate = contacts.gate(&preview.operation, &owner).unwrap();
        facade
            .run_gate(gate, &owner.subject, gate.input(), 100, &check)
            .await
            .unwrap();
        drop(contacts);
        // Simulate a pre-binding migration history in this disposable fixture,
        // while retaining actual authenticated gate/fingerprint records.
        database
            .community("global")
            .unwrap()
            .execute(
                "DELETE FROM cvld_contact_key_binding WHERE domain = ?1",
                crlt::params![cgbl::contacts::ContactDomain::Phone.as_str()],
            )
            .await
            .unwrap();
        assert!(matches!(
            Contacts::with_transport(
                &database,
                "global",
                &cfg,
                Time::new(),
                Fixture(Wire::new([]))
            )
            .await,
            Err(Error::Migration)
        ));
        let markers = database
            .community("global")
            .unwrap()
            .query(
                "SELECT domain FROM cvld_contact_key_binding WHERE domain = ?1",
                crlt::params![cgbl::contacts::ContactDomain::Phone.as_str()],
            )
            .await
            .unwrap();
        assert!(markers.is_empty());
    }
}
