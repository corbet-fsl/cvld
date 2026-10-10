//! Actual HTTP routes refuse absent providers and keep local simulation separate.
#![cfg(feature = "development-gate")]
mod support;
use cvld::{api::*, config::Config, service::Door};
use serde_json::json;
use support::*;

struct InertHttp {
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

async fn production(allowed: bool) -> (Running, std::sync::Arc<InertHttp>, u64) {
    use cvld::contact_gates::{
        Amount, Channel, ContactConfig, Coverage, ProviderConfig, Tariff, transport::AnyTransport,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut config = global_config(dir.path(), 200).await;
    let cohort = (NOW / 86400 + 40) * 86400;
    let mut rng = cpsd::rand::rngs::OsRng;
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("production-contact-fixture").unwrap(),
        ["cphn", "cmbx"]
            .map(|gate| cpsd::GateId::new(gate).unwrap())
            .to_vec(),
    )
    .unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_production_registry_uses_real_leaf_parsing_and_issues_a_blind_passport() {
    let (service, wire, cohort) = production(true).await;
    let member = enrol(&service, WALLET, None).await;
    let api = client(&service, WALLET, Some(&member.session));
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
                &service,
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
    assert_eq!(wire.calls.load(std::sync::atomic::Ordering::SeqCst), 4);
    let public: GlobalPublic =
        serde_json::from_value(api.call("global_public", json!({})).await.unwrap()).unwrap();
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut rng = cpsd::rand::rngs::OsRng;
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let challenge: Bytes =
        serde_json::from_value(api.call("passport_challenge", json!({})).await.unwrap()).unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let (request, pending) = cpsd::request_issue(&mut rng, &secret, &issuer, &challenge).unwrap();
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
    let presentation_request = cpsd::PresentationRequest::for_epoch(
        &mut rng,
        cpsd::CommunityId::new(b"consumer").unwrap(),
        1,
        [
            cpsd::GateId::new("cphn").unwrap(),
            cpsd::GateId::new("cmbx").unwrap(),
        ],
        NOW,
        cohort,
    )
    .unwrap();
    let proof = trusted_presentation(&passport, &presentation_request).await;
    assert_eq!(
        cpsd::verify(&mut rng, &[issuer], &presentation_request, &proof).unwrap(),
        secret.pseudonym(presentation_request.community())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_policy_and_operator_cost_caps_refuse_before_any_provider_http() {
    let (service, wire, _) = production(false).await;
    let member = enrol(&service, WALLET, None).await;
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "contact_plan",
            plan("phone", "+12025550123", 10)
        )
        .await,
        409
    );
    assert_eq!(wire.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let (service, wire, _) = production(true).await;
    let member = enrol(&service, WALLET, None).await;
    for body in [plan("phone", "+12025550123", 21), {
        let mut body = plan("phone", "+12025550123", 10);
        body["max_attempts"] = json!(4);
        body
    }] {
        assert_eq!(
            call_status(
                &service,
                WALLET,
                Some(&member.session),
                "contact_plan",
                body
            )
            .await,
            409
        );
    }
    assert_eq!(wire.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unconfigured_contacts_remain_disabled_and_all_routes_require_the_wallet_host() {
    let service = global(200).await;
    let member = enrol(&service, WALLET, None).await;
    let plan = json!({"options":["not-enabled"],"destination":"+12025550123","budget":{"unit":"FIXTURE","scale":0,"atoms":10},"max_attempts":2,"order":"configured"});
    for (action, body) in [
        ("contact_plan", plan.clone()),
        (
            "contact_check",
            json!({"operation":"absent","code":"123456"}),
        ),
        (
            "contact_execute",
            json!({"operation":"absent","authorization":"absent"}),
        ),
        ("contact_status", json!({"operation":"absent"})),
        ("contact_accept", json!({"operation":"absent"})),
    ] {
        assert_eq!(
            call_status(&service, WALLET, None, action, body.clone()).await,
            401
        );
        assert_eq!(
            call_status(&service, ROOT, Some(&member.session), action, body.clone()).await,
            401
        );
        assert_eq!(
            call_status(&service, WALLET, Some(&member.session), action, body).await,
            409
        );
    }
    let public: GlobalPublic = serde_json::from_value(
        client(&service, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community("alpha", &public).await;
    assert_eq!(
        call_status(
            &community,
            "api.alpha.example.test",
            None,
            "contact_plan",
            plan
        )
        .await,
        421
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_simulation_exercises_real_planning_but_never_creates_a_dispatch_or_gate() {
    let service = global(200).await;
    let member = enrol(&service, WALLET, None).await;
    let api = client(&service, WALLET, Some(&member.session));
    let request = json!({"destination":"+12025550123","offers":[{"channel":"sms","maximum":{"unit":"FIXTURE","scale":0,"atoms":4},"exact":false,"source":"explicit hypothetical fixture","valid_until":NOW+60,"outcome":"safe_failure"},{"channel":"call","maximum":{"unit":"FIXTURE","scale":0,"atoms":3},"exact":false,"source":"explicit hypothetical fixture","valid_until":NOW+60,"outcome":"success"}],"budget":{"unit":"FIXTURE","scale":0,"atoms":10},"max_attempts":2,"order":"configured"});
    let simulated = api.call("contact_simulate", request.clone()).await.unwrap();
    assert_eq!(simulated["simulated"], true);
    assert_eq!(simulated["outcome"], "success");
    assert_eq!(simulated["attempts"], 2);
    assert_eq!(simulated["exposure"]["atoms"], 7);
    for private in ["operation", "comparison", "destination", "credential"] {
        assert!(simulated.get(private).is_none());
    }
    let mut unknown = request.clone();
    unknown["offers"][0]["maximum"] = serde_json::Value::Null;
    unknown["offers"][1]["maximum"] = serde_json::Value::Null;
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "contact_simulate",
            unknown
        )
        .await,
        409
    );
    let mut mixed = request;
    mixed["offers"][1]["channel"] = json!("email");
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "contact_simulate",
            mixed
        )
        .await,
        400
    );
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "contact_accept",
            json!({"operation":"simulated","verified":true})
        )
        .await,
        400
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_contacts_require_explicit_limits_keys_credentials_and_valid_tariff_provenance()
{
    let directory = tempfile::tempdir().unwrap();
    let cfg = global_config(directory.path(), 200).await;
    let mut serialized = serde_json::to_value(cfg).unwrap();
    // Old configuration remains inert: no contact block is discovered or enabled.
    serialized.as_object_mut().unwrap().remove("contacts");
    let inert: Config = serde_json::from_value(serialized.clone()).unwrap();
    assert!(inert.contacts.is_none());
    serialized["contacts"] = json!({"providers":[],"phone_identity_key_file":null,"mailbox_identity_key_file":null,"capacity":10,"budget":{"unit":"FIXTURE","scale":0,"atoms":10},"max_attempts":2,"transport_timeout_seconds":5});
    assert!(serde_json::from_value::<Config>(serialized.clone()).is_err());
    serialized["contacts"]["ceremony_seconds"] = json!(60);
    serialized["contacts"]["providers"] = json!([{"id":"phone","provider":"twilio","account":format!("AC{}","0".repeat(32)),"service":format!("VA{}","0".repeat(32)),"credential_file":directory.path().join("missing-secret"),"channel":"sms","begin":{"coverage":"all_accepted_requests","maximum":{"unit":"FIXTURE","scale":0,"atoms":4},"exact":false,"source":"operator configured fixture cap","scope":"fixture only, all failures/delivery changes","valid_until":NOW+60},"check":{"coverage":"all_accepted_requests","maximum":{"unit":"FIXTURE","scale":0,"atoms":3},"exact":false,"source":"operator configured fixture cap","scope":"fixture only, all failures/delivery changes","valid_until":NOW+60}}]);
    let configured: Config = serde_json::from_value(serialized.clone()).unwrap();
    assert!(
        Door::global(
            configured,
            std::sync::Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)))
        )
        .await
        .is_err()
    );
    // Malformed price provenance also refuses startup before any dispatch.
    serialized["contacts"]["providers"][0]["begin"]["source"] = json!("");
    let configured: Config = serde_json::from_value(serialized).unwrap();
    assert!(
        Door::global(
            configured,
            std::sync::Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)))
        )
        .await
        .is_err()
    );
}
