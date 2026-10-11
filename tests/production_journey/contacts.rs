//! Production contact setup mirrors the existing genuine HTTP route fixture.
//! Only the external Twilio HTTP boundary is inert; policy, costs, Keyhole,
//! global facts, storage and blind issuance use their actual owners.
use super::*;

pub(super) struct InertHttp {
    calls: std::sync::atomic::AtomicUsize,
    clock: std::sync::Arc<TestClock>,
}
impl cvld::contact_gates::transport::TrustedTransport for InertHttp {
    fn mode(&self) -> cfbk::cost::Mode {
        cfbk::cost::Mode::Production
    }
    fn phone(
        &self,
        request: axum::http::Request<cphn::Private>,
    ) -> cvld::contact_gates::transport::PhoneFuture<'_> {
        Box::pin(async move {
            use cvld::service::Clock;
            assert!(
                request
                    .extensions()
                    .get::<cphn::DispatchDeadline>()
                    .unwrap()
                    .valid_until
                    > self.clock.now()
            );
            assert!(request.headers()[axum::http::header::AUTHORIZATION].is_sensitive());
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let checking = request.uri().path().ends_with("/VerificationCheck");
            Ok(axum::http::Response::new(cphn::Private::new(serde_json::to_vec(&json!({"sid":format!("VE{}","0".repeat(32)),"account_sid":format!("AC{}","0".repeat(32)),"service_sid":format!("VA{}","0".repeat(32)),"to":"+12025550123","channel":"sms","status":if checking {"approved"} else {"pending"},"valid":checking,"extension":"private-inert-upstream"})).unwrap())))
        })
    }
    fn mailbox(
        &self,
        request: axum::http::Request<cmbx::Private>,
    ) -> cvld::contact_gates::transport::MailboxFuture<'_> {
        Box::pin(async move {
            use cvld::service::Clock;
            assert!(
                request
                    .extensions()
                    .get::<cmbx::DispatchDeadline>()
                    .unwrap()
                    .valid_until
                    > self.clock.now()
            );
            assert!(request.headers()[axum::http::header::AUTHORIZATION].is_sensitive());
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let checking = request.uri().path().ends_with("/VerificationCheck");
            Ok(axum::http::Response::new(cmbx::Private::new(serde_json::to_vec(&json!({"sid":format!("VE{}","0".repeat(32)),"account_sid":format!("AC{}","0".repeat(32)),"service_sid":format!("VA{}","0".repeat(32)),"to":"Member+alias@example.test","channel":"email","status":if checking {"approved"} else {"pending"},"valid":checking,"extension":"private-inert-upstream"})).unwrap())))
        })
    }
}

pub(super) async fn production(allowed: bool) -> (Running, std::sync::Arc<InertHttp>, u64) {
    let issuer = cpsd::IssuerKey::generate(
        &mut cpsd::rand::rngs::OsRng,
        cpsd::KeyId::new("production-contact-fixture").unwrap(),
        ["cphn", "cmbx"]
            .map(|gate| cpsd::GateId::new(gate).unwrap())
            .to_vec(),
    )
    .unwrap();
    production_with_issuer(allowed, &issuer).await
}

pub(super) async fn production_with_issuer(
    allowed: bool,
    issuer: &cpsd::IssuerKey,
) -> (Running, std::sync::Arc<InertHttp>, u64) {
    use cvld::contact_gates::{
        Amount, Channel, ContactConfig, Coverage, ProviderConfig, Tariff, transport::AnyTransport,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut config = global_config(dir.path(), 200).await;
    let cohort = (NOW / 86400 + 40) * 86400;
    std::fs::write(&config.issuer_key_file, issuer.to_secret_bytes()).unwrap();
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "policy-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        NOW - 1,
        86400 * 100,
    )
    .await
    .unwrap();
    let policy = cgbl::Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: cohort,
        gates: ["cphn", "cmbx"]
            .map(|gate| cgbl::GatePolicy {
                gate: gate.into(),
                provider: if allowed {
                    "twilio"
                } else {
                    "policy-disabled-provider"
                }
                .into(),
                uniqueness: true,
            })
            .to_vec(),
    };
    let signed = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            NOW,
            cohort + 1,
        )
        .await
        .unwrap();
    std::fs::write(&config.policy_file, signed).unwrap();
    std::fs::write(
        &config.policy_authority_file,
        authority.key_ring().unwrap().to_cbor(),
    )
    .unwrap();
    let secret = dir.path().join("inert-provider-secret");
    std::fs::write(&secret, b"private-inert-provider-secret").unwrap();
    let key = dir.path().join("stable-contact-key");
    std::fs::write(&key, [8; 32]).unwrap();
    let amount = |atoms| Amount {
        unit: "FIXTURE".into(),
        scale: 0,
        atoms,
    };
    let tariff = |atoms| Tariff {
        coverage: Coverage::AllAcceptedRequests,
        maximum: amount(atoms),
        exact: false,
        source: "inert operator-configured test cap; no vendor price claim".into(),
        scope: "fixture only, account/service/channel, failures and delivery changes".into(),
        valid_until: NOW + 300,
    };
    config.contacts = Some(ContactConfig {
        providers: [("phone", Channel::Sms), ("mailbox", Channel::Email)]
            .into_iter()
            .map(|(id, channel)| ProviderConfig {
                id: id.into(),
                provider: "twilio".into(),
                account: format!("AC{}", "0".repeat(32)),
                service: format!("VA{}", "0".repeat(32)),
                credential_file: secret.to_str().unwrap().into(),
                channel,
                begin: tariff(4),
                check: tariff(3),
            })
            .collect(),
        phone_identity_key_file: Some(key.to_str().unwrap().into()),
        mailbox_identity_key_file: Some(key.to_str().unwrap().into()),
        capacity: 10,
        ceremony_seconds: 120,
        budget: amount(20),
        max_attempts: 3,
        transport_timeout_seconds: 5,
    });
    config.development = false;
    let clock = std::sync::Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)));
    let wire = std::sync::Arc::new(InertHttp {
        calls: std::sync::atomic::AtomicUsize::new(0),
        clock: clock.clone(),
    });
    let door =
        Door::global_with_contact_transport(config, clock.clone(), AnyTransport::new(wire.clone()))
            .await
            .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (
        Running {
            base,
            door,
            clock,
            task,
            dir,
        },
        wire,
        cohort,
    )
}

fn plan(option: &str, destination: &str, atoms: u64) -> serde_json::Value {
    json!({"options":[option],"destination":destination,"budget":{"unit":"FIXTURE","scale":0,"atoms":atoms},"max_attempts":3,"order":"configured"})
}

impl InertHttp {
    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

pub(super) async fn wallet(
    service: &Running,
    cohort: u64,
) -> (Member, cpsd::Passport, GlobalPublic) {
    let secret = cpsd::HolderSecret::generate(&mut cpsd::rand::rngs::OsRng);
    wallet_with_holder(service, cohort, &secret).await
}

pub(super) async fn wallet_with_holder(
    service: &Running,
    cohort: u64,
    secret: &cpsd::HolderSecret,
) -> (Member, cpsd::Passport, GlobalPublic) {
    let member = enrol(service, WALLET, None).await;
    let api = client(service, WALLET, Some(&member.session));
    for (option, destination, gate) in [
        ("phone", "+12025550123", "cphn"),
        ("mailbox", "Member+alias@EXAMPLE.test", "cmbx"),
    ] {
        let preview = api
            .call("contact_plan", plan(option, destination, 10))
            .await
            .unwrap();
        assert_eq!(preview["offers"][0]["option"], option);
        let pending = api
            .call(
                "contact_execute",
                json!({"operation":preview["operation"],"authorization":preview["authorization"]}),
            )
            .await
            .unwrap();
        assert_eq!(pending["outcome"], "pending");
        assert_eq!(pending["exposure"]["atoms"], 4);
        let finish = api
            .call(
                "contact_check",
                json!({"operation":preview["operation"],"code":"123456"}),
            )
            .await
            .unwrap();
        assert_eq!(
            call_status(
                service,
                WALLET,
                Some(&member.session),
                "contact_execute",
                json!({"operation":preview["operation"],"authorization":preview["authorization"]})
            )
            .await,
            409
        );
        let verified = api
            .call(
                "contact_execute",
                json!({"operation":finish["operation"],"authorization":finish["authorization"]}),
            )
            .await
            .unwrap();
        assert_eq!(verified["outcome"], "verified");
        assert_eq!(verified["exposure"]["atoms"], 7);
        for _ in 0..2 {
            let accepted = api
                .call("contact_accept", json!({"operation":preview["operation"]}))
                .await
                .unwrap();
            assert_eq!(accepted["gate"], gate);
            assert_eq!(accepted["valid_until"], cohort);
        }
        for body in [&preview, &pending, &finish, &verified] {
            let encoded = serde_json::to_string(body).unwrap();
            for raw in [
                destination,
                "123456",
                "private-inert-provider-secret",
                "private-inert-upstream",
            ] {
                assert!(!encoded.contains(raw));
            }
        }
    }
    let public: GlobalPublic =
        serde_json::from_value(api.call("global_public", json!({})).await.unwrap()).unwrap();
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut rng = cpsd::rand::rngs::OsRng;
    let challenge: Bytes =
        serde_json::from_value(api.call("passport_challenge", json!({})).await.unwrap()).unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let (request, pending) = cpsd::request_issue(&mut rng, secret, &issuer, &challenge).unwrap();
    let issued: Bytes = serde_json::from_value(
        api.call(
            "passport_issue",
            json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes()}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let passport = pending
        .finish(&cpsd::BlindPassport::from_bytes(&issued.bytes).unwrap())
        .unwrap();
    (member, passport, public)
}
