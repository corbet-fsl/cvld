#![allow(dead_code)]
pub mod client_faults;
pub mod resident;

use cvld::{
    api::*,
    cli::Client,
    config::Config,
    service::{Clock, Door},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

pub const NOW: u64 = 1_800_000_000;
pub const DOMAIN: &str = "example.test";
pub const WALLET: &str = "wallet.example.test";
pub const ROOT: &str = "api.root.example.test";
pub struct TestClock(pub AtomicU64);
impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
impl TestClock {
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}
pub struct Running {
    pub base: String,
    pub door: Door,
    pub clock: Arc<TestClock>,
    pub task: tokio::task::JoinHandle<()>,
    pub dir: tempfile::TempDir,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_owned()
}
pub async fn global(burst: u32) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = cpsd::rand::rngs::OsRng;
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("global-test").unwrap(),
        vec![cpsd::GateId::new("development").unwrap()],
    )
    .unwrap();
    let policy = cglb::Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: (NOW / 86_400 + 40) * 86_400,
        gates: vec![cglb::GatePolicy {
            gate: "development".into(),
            provider: "cglb.test".into(),
            uniqueness: true,
        }],
    };
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "policy-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        NOW - 1,
        86_400 * 100,
    )
    .await
    .unwrap();
    let signed = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            NOW,
            policy.shared_expiry + 1,
        )
        .await
        .unwrap();
    let config = Config {
        listen: "127.0.0.1:0".into(),
        domain: DOMAIN.into(),
        database_url: format!("file://{}", dir.path().join("global.db").display()),
        database_token_file: None,
        signing_seed_file: write(dir.path(), "signer", &[4; 32]),
        issuer_key_file: write(dir.path(), "issuer", &issuer.to_secret_bytes()),
        uniqueness_key_file: write(dir.path(), "unique", &[5; 32]),
        policy_file: write(dir.path(), "policy", &signed),
        policy_authority_file: write(
            dir.path(),
            "authority",
            &authority.key_ring().unwrap().to_cbor(),
        ),
        root_user: "00000000-0000-4000-8000-000000000001".into(),
        root_bootstrap_file: Some(write(
            dir.path(),
            "bootstrap",
            b"synthetic-operator-enrolment-capability",
        )),
        session_seconds: 600,
        pending_capacity: 100,
        throttle_burst: burst,
        throttle_interval_ms: 60_000,
        publication_seconds: 172800,
        signer_max_seconds: 86_400 * 100,
        development: true,
    };
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let door = Door::global(config, clock.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Running {
        base,
        door,
        clock,
        task,
        dir,
    }
}
pub fn client(service: &Running, host: &str, token: Option<&str>) -> Client {
    Client::new(service.base.clone(), host.into(), token.map(str::to_owned)).unwrap()
}
pub struct Member {
    pub authenticator: SoftToken,
    pub user: String,
    pub credential: Vec<u8>,
    pub session: String,
    pub signing_key: [u8; 32],
}
pub async fn enrol(service: &Running, host: &str, bootstrap: Option<&str>) -> Member {
    let client = client(service, host, None);
    let start: Ceremony = serde_json::from_value(
        client
            .call(
                "register_begin",
                json!({"bootstrap":bootstrap,"passport":null}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let mut authenticator = SoftToken::new(true).unwrap().0;
    let challenge: ckyh::CreationChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = authenticator
        .perform_register(
            ckyh::Url::parse(&format!("https://{host}")).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
                let mut options = challenge.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();
    let credential_id = credential.raw_id.as_ref().to_vec();
    let user: User = serde_json::from_value(
        client
            .call(
                "register_finish",
                json!({"ceremony":start.ceremony,"credential":credential}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let session = login(
        service,
        host,
        &mut authenticator,
        &user.user,
        &credential_id,
    )
    .await;
    Member {
        authenticator,
        user: user.user,
        credential: credential_id,
        session,
        signing_key: SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes(),
    }
}
pub async fn login(
    service: &Running,
    host: &str,
    authenticator: &mut SoftToken,
    user: &str,
    credential: &[u8],
) -> String {
    let client = client(service, host, None);
    let start: Ceremony = serde_json::from_value(
        client
            .call("login_begin", json!({"user":user,"credential":credential}))
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge: ckyh::RequestChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = authenticator
        .perform_auth(
            ckyh::Url::parse(&format!("https://{host}")).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    let session: Session = serde_json::from_value(
        client
            .call(
                "login_finish",
                json!({"ceremony":start.ceremony,"credential":credential}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    session.token
}
pub async fn call_status(
    service: &Running,
    host: &str,
    token: Option<&str>,
    name: &str,
    body: Value,
) -> u16 {
    let mut request = reqwest::Client::new()
        .post(format!("{}/v1/{name}", service.base))
        .header("host", host)
        .json(&body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().await.unwrap().status().as_u16()
}

/// Synthetic authenticated community for wallet-only cryptographic tests.
/// Full community tests obtain this signature and ring over the real HTTP door.
pub async fn trusted_presentation(
    passport: &cpsd::Passport,
    request: &cpsd::PresentationRequest,
) -> cpsd::Presentation {
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "synthetic-community",
        csgn::SecretKey::from_seed(&mut [8; 32]),
        NOW - 1,
        86400,
    )
    .await
    .unwrap();
    let signed = signer
        .sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            NOW,
            request.now() + 1,
        )
        .await
        .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        request.community().clone(),
        signer.key_ring().unwrap().clone(),
    );
    passport
        .present(&mut cpsd::rand::rngs::OsRng, &expected, &signed, NOW)
        .unwrap()
}

use cmty::{cplc, cplc::crbk};
use cvld::config::{CommunityConfig, Operator};
use ed25519_dalek::{Signer, SigningKey};

pub fn community_rules() -> crbk::Rulebook {
    let mut rules = crbk::Rulebook::default();
    crbk::define_membership_settings(&mut rules).unwrap();
    for (level, gate, provider) in [
        (
            crbk::GateLevel::Global,
            "development",
            cmty::PASSPORT_PROVIDER,
        ),
        (crbk::GateLevel::Community, "cvch", "sponsor"),
    ] {
        for key in [
            crbk::gate_key(level, gate),
            crbk::provider_key(level, gate, provider),
        ] {
            rules
                .define(
                    key,
                    crbk::Setting {
                        value_type: crbk::SettingType::Boolean,
                        nullable: false,
                        default: json!(true),
                        bounds: crbk::Bounds::default(),
                        lowest_layer: crbk::Layer::Community,
                        kind: crbk::SettingKind::Technical,
                    },
                )
                .unwrap();
        }
    }
    rules
        .define(
            crbk::action_key(cmty::ADMISSION_ACTION),
            crbk::Setting {
                value_type: crbk::SettingType::Policy,
                nullable: false,
                default: serde_json::to_value(crbk::ActionPolicy {
                    all_of: vec![
                        crbk::Requirement {
                            gate: "development".into(),
                            level: crbk::GateLevel::Global,
                            provider: None,
                        },
                        crbk::Requirement {
                            gate: "cvch".into(),
                            level: crbk::GateLevel::Community,
                            provider: None,
                        },
                    ],
                    ..Default::default()
                })
                .unwrap(),
                bounds: crbk::Bounds::default(),
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    for (key, value_type, default, bounds) in [
        (
            "handles.reserved",
            crbk::SettingType::Array,
            json!(["root", "admin"]),
            crbk::Bounds::default(),
        ),
        (
            "quota",
            crbk::SettingType::Integer,
            json!(10),
            crbk::Bounds {
                min: Some(1.into()),
                max: Some(100.into()),
            },
        ),
    ] {
        rules
            .define(
                key,
                crbk::Setting {
                    value_type,
                    nullable: false,
                    default,
                    bounds,
                    lowest_layer: crbk::Layer::Community,
                    kind: crbk::SettingKind::Technical,
                },
            )
            .unwrap();
    }
    rules
}
pub fn community_schema(community: &str, version: u32) -> cplc::cshm::Schema {
    serde_json::from_value(json!({"community":community,"version":version,
        "public":[{"id":"restricted","label":"Restricted", "kind":{"type":"yes_no"},"required":false,"filterable":false,"change_preset":"stable","no_contact_details":false}],"private":[]})).unwrap()
}
pub async fn community(name: &str, public: &GlobalPublic) -> Running {
    community_with_burst(name, public, 100).await
}
pub async fn community_with_burst(name: &str, public: &GlobalPublic, burst: u32) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let config = CommunityConfig {
        listen: "127.0.0.1:0".into(),
        domain: DOMAIN.into(),
        community: name.into(),
        database_url: format!("file://{}", dir.path().join("community.db").display()),
        database_token_file: None,
        signing_seed_file: write(dir.path(), "signer", &[name.as_bytes()[0]; 32]),
        rulebook_file: write(
            dir.path(),
            "rulebook",
            &serde_json::to_vec(&community_rules()).unwrap(),
        ),
        schema_file: write(
            dir.path(),
            "schema",
            &serde_json::to_vec(&community_schema(name, 1)).unwrap(),
        ),
        global_key_ring_file: write(dir.path(), "global-ring", &public.key_ring),
        global_status_file: write(dir.path(), "global-status", &public.status),
        minimum_global_epoch: 1,
        minimum_global_revision: 1,
        global_gates: vec!["development".into()],
        root: Operator {
            user: "00000000-0000-4000-8000-000000000001".into(),
            bootstrap_file: Some(write(
                dir.path(),
                "root-bootstrap",
                b"synthetic-root-enrolment-capability",
            )),
        },
        admin: Operator {
            user: "00000000-0000-4000-8000-000000000002".into(),
            bootstrap_file: Some(write(
                dir.path(),
                "admin-bootstrap",
                b"synthetic-admin-enrolment-capability",
            )),
        },
        pending_days: 2,
        lease_months: 1,
        session_seconds: 600,
        pending_capacity: 100,
        throttle_burst: burst,
        throttle_interval_ms: 60_000,
        publication_seconds: 2 * 86_400,
        signer_max_seconds: 10 * 366 * 86_400,
        minimum_notice_seconds: 0,
        voucher_provider: "sponsor".into(),
        voucher_public_key_file: write(
            dir.path(),
            "voucher-key",
            SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes(),
        ),
    };
    write(
        dir.path(),
        "config.json",
        &serde_json::to_vec(&config).unwrap(),
    );
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let door = Door::community(config, clock.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Running {
        base,
        door,
        clock,
        task,
        dir,
    }
}
pub async fn wallet_passport(service: &Running) -> (Member, cpsd::Passport, GlobalPublic) {
    let member = enrol(service, WALLET, None).await;
    let client = client(service, WALLET, Some(&member.session));
    client.call("development_gate", json!({})).await.unwrap();
    let public: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut rng = cpsd::rand::rngs::OsRng;
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let challenge: Bytes =
        serde_json::from_value(client.call("passport_challenge", json!({})).await.unwrap())
            .unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let (request, pending) = cpsd::request_issue(&mut rng, &secret, &issuer, &challenge).unwrap();
    let response: Bytes = serde_json::from_value(
        client
            .call(
                "passport_issue",
                json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes()}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let passport = pending
        .finish(&cpsd::BlindPassport::from_bytes(&response.bytes).unwrap())
        .unwrap();
    (member, passport, public)
}
pub async fn presentation(
    service: &Running,
    host: &str,
    session: Option<&str>,
    passport: &cpsd::Passport,
) -> PresentationInput {
    let challenge: PresentationChallenge = serde_json::from_value(
        client(service, host, session)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let feed: TrustFeed = serde_json::from_value(
        client(service, host, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = host
        .strip_prefix("api.")
        .unwrap()
        .split('.')
        .next()
        .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new(community).unwrap(),
        csgn::KeyRing::from_cbor(&feed.key_ring).unwrap(),
    );
    let proof = passport
        .present(
            &mut cpsd::rand::rngs::OsRng,
            &expected,
            &challenge.request,
            service.clock.now(),
        )
        .unwrap();
    PresentationInput {
        challenge: challenge.challenge,
        proof: proof.to_bytes(),
    }
}
pub async fn enrol_community(service: &Running, host: &str, passport: &cpsd::Passport) -> Member {
    let proof = presentation(service, host, None, passport).await;
    let body = json!({"passport":proof});
    let start: Ceremony = serde_json::from_value(
        client(service, host, None)
            .call("register_begin", body.clone())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        call_status(service, host, None, "register_begin", body).await,
        409
    );
    finish_enrol(service, host, start).await
}
pub async fn finish_enrol(service: &Running, host: &str, start: Ceremony) -> Member {
    let mut authenticator = SoftToken::new(true).unwrap().0;
    let challenge: ckyh::CreationChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = authenticator
        .perform_register(
            ckyh::Url::parse(&format!("https://{host}")).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
                let mut options = challenge.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();
    let credential_id = credential.raw_id.as_ref().to_vec();
    let user: User = serde_json::from_value(
        client(service, host, None)
            .call(
                "register_finish",
                json!({"ceremony":start.ceremony,"credential":credential}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let session = login(
        service,
        host,
        &mut authenticator,
        &user.user,
        &credential_id,
    )
    .await;
    let signing_key = SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes();
    client(service, host, Some(&session))
        .call("device_authorize", json!({"key": signing_key}))
        .await
        .unwrap();
    Member {
        authenticator,
        user: user.user,
        credential: credential_id,
        session,
        signing_key: SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes(),
    }
}
pub fn voucher(community: &str, member: &str, id: &str, valid_until: u64) -> Value {
    let binding = cvch::member_binding(&cvch::receipt_id(id), member.as_bytes());
    let signature = SigningKey::from_bytes(&[9; 32])
        .sign(&cvch::issuance_bytes(id, valid_until, community, &binding))
        .to_bytes()
        .to_vec();
    json!({"id":id,"valid_until":valid_until,"member_binding":binding,"signature":signature})
}
pub async fn issue_community(
    service: &Running,
    host: &str,
    member: &Member,
    passport: &cpsd::Passport,
) -> CredentialResponse {
    let proof = presentation(service, host, Some(&member.session), passport).await;
    serde_json::from_value(
        client(service, host, Some(&member.session))
            .call(
                "credential_issue",
                json!({"presentation":proof,"devices":[member.signing_key]}),
            )
            .await
            .unwrap(),
    )
    .unwrap()
}
