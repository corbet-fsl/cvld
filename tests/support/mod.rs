#![allow(dead_code)]
pub mod active;
pub mod resident;
pub mod self_ban;

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
// Day-aligned fixtures once hid second-precision signing defects: keep it off the boundary.
const _: () = assert!(!NOW.is_multiple_of(86_400));
pub const DOMAIN: &str = "example.test";
pub const WALLET: &str = "wallet.example.test";
/// Page origin of a passkey ceremony: the wallet's runs in the vault frame.
pub fn origin_for(host: &str) -> String {
    if host.starts_with("wallet.") {
        format!("https://vault.{host}")
    } else {
        format!("https://{host}")
    }
}
pub const ROOT: &str = "api.admin.root.example.test";
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
pub async fn global_config(dir: &Path, burst: u32) -> Config {
    global_config_at(dir, burst, NOW).await
}
pub async fn global_config_at(dir: &Path, burst: u32, now: u64) -> Config {
    let mut rng = cpsd::rand::rngs::OsRng;
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("global-test").unwrap(),
        vec![cpsd::GateId::new("development").unwrap()],
    )
    .unwrap();
    let policy = cgbl::Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: (now / 86_400 + 40) * 86_400,
        gates: vec![cgbl::GatePolicy {
            gate: "development".into(),
            provider: "cgbl.test".into(),
            uniqueness: true,
        }],
    };
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "policy-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        now - 1,
        86_400 * 100,
    )
    .await
    .unwrap();
    let signed = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            now,
            policy.shared_expiry + 1,
        )
        .await
        .unwrap();
    Config {
        wallet: None,
        listen: "127.0.0.1:0".into(),
        domain: DOMAIN.into(),
        database_url: format!("file://{}", dir.join("global.db").display()),
        database_token_file: None,
        signing_seed_file: write(dir, "signer", &[4; 32]),
        issuer_key_file: write(dir, "issuer", &issuer.to_secret_bytes()),
        uniqueness_key_file: write(dir, "unique", &[5; 32]),
        policy_file: write(dir, "policy", &signed),
        policy_authority_file: write(dir, "authority", &authority.key_ring().unwrap().to_cbor()),
        root_user: "00000000-0000-4000-8000-000000000001".into(),
        root_bootstrap_file: Some(write(
            dir,
            "bootstrap",
            b"synthetic-operator-enrolment-capability",
        )),
        shutdown_seconds: 30,
        session_seconds: 600,
        pending_capacity: 100,
        throttle_burst: burst,
        throttle_interval_ms: 60_000,
        trusted_proxies: Vec::new(),
        ohttp: None,
        publication_seconds: 172800,
        signer_max_seconds: 86_400 * 100,
        development: true,
        contacts: None,
    }
}
pub async fn global(burst: u32) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let config = global_config(dir.path(), burst).await;
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let door = Door::global(config, clock.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let running = Running {
        base,
        door,
        clock,
        task,
        dir,
    };
    active::register(&running).await;
    running
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
    if host == ROOT && active::is_registered(service) {
        return active::root_member(service, bootstrap).await;
    }
    enrol_raw(service, host, bootstrap).await
}
pub async fn enrol_raw(service: &Running, host: &str, bootstrap: Option<&str>) -> Member {
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
            ckyh::Url::parse(&origin_for(host)).unwrap(),
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
            ckyh::Url::parse(&origin_for(host)).unwrap(),
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
/// A fresh user-verifying assertion for exactly one action: the `step_up` proof
/// that `passkey_add` (begin), `passkey_revoke` and the device actions require.
pub async fn step_up(
    service: &Running,
    host: &str,
    session: &str,
    authenticator: &mut SoftToken,
    action: Value,
) -> Value {
    let begin: cvld::api::StepUpChallenge = serde_json::from_value(
        client(service, host, Some(session))
            .call("step_up_begin", json!({"action":action}))
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge: ckyh::RequestChallengeResponse = serde_json::from_value(begin.options).unwrap();
    let credential = authenticator
        .perform_auth(
            ckyh::Url::parse(&origin_for(host)).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    json!({"ceremony":begin.ceremony,"credential":credential})
}
/// `body` with the proof for `action` added as its `step_up` field.
pub async fn proven(
    service: &Running,
    host: &str,
    session: &str,
    authenticator: &mut SoftToken,
    action: Value,
    mut body: Value,
) -> Value {
    body["step_up"] = step_up(service, host, session, authenticator, action).await;
    body
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
use ed25519_dalek::SigningKey;

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
pub fn community_config(
    dir: &Path,
    name: &str,
    public: &GlobalPublic,
    burst: u32,
) -> CommunityConfig {
    let config = CommunityConfig {
        stamp_cohort_seconds: None,
        founding_seed: None,
        listen: "127.0.0.1:0".into(),
        domain: DOMAIN.into(),
        community: name.into(),
        database_url: format!("file://{}", dir.join("community.db").display()),
        database_token_file: None,
        signing_seed_file: write(dir, "signer", &[name.as_bytes()[0]; 32]),
        rulebook_file: write(
            dir,
            "rulebook",
            &serde_json::to_vec(&community_rules()).unwrap(),
        ),
        schema_file: write(
            dir,
            "schema",
            &serde_json::to_vec(&community_schema(name, 1)).unwrap(),
        ),
        global_key_ring_file: write(dir, "global-ring", &public.key_ring),
        global_status_file: write(dir, "global-status", &public.status),
        minimum_global_epoch: 1,
        minimum_global_revision: 1,
        global_gates: vec!["development".into()],
        root: Operator {
            user: "00000000-0000-4000-8000-000000000001".into(),
            bootstrap_file: Some(write(
                dir,
                "root-bootstrap",
                b"synthetic-root-enrolment-capability",
            )),
        },
        admin: Operator {
            user: "00000000-0000-4000-8000-000000000002".into(),
            bootstrap_file: Some(write(
                dir,
                "admin-bootstrap",
                b"synthetic-admin-enrolment-capability",
            )),
        },
        pending_days: 2,
        lease_months: 1,
        shutdown_seconds: 30,
        session_seconds: 600,
        pending_capacity: 100,
        throttle_burst: burst,
        throttle_interval_ms: 60_000,
        trusted_proxies: Vec::new(),
        ohttp: None,
        publication_seconds: 2 * 86_400,
        signer_max_seconds: 10 * 366 * 86_400,
        minimum_notice_seconds: 0,
        voucher_provider: "sponsor".into(),
        payments: None,
        accounting: None,
        creation: None,
        shared_database: false,
    };
    write(dir, "config.json", &serde_json::to_vec(&config).unwrap());
    config
}
pub async fn community_with_burst(name: &str, public: &GlobalPublic, burst: u32) -> Running {
    let running = community_unfounded_with_burst(name, public, burst).await;
    active::found(&running, name, public).await;
    running
}
/// A community that admits nobody yet: only tests of founding itself use it.
pub async fn community_unfounded(name: &str, public: &GlobalPublic) -> Running {
    community_unfounded_with_burst(name, public, 100).await
}
pub async fn community_unfounded_with_burst(
    name: &str,
    public: &GlobalPublic,
    burst: u32,
) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let config = community_config(dir.path(), name, public, burst);
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
            ckyh::Url::parse(&origin_for(host)).unwrap(),
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
    let body = proven(
        service,
        host,
        &session,
        &mut authenticator,
        json!({"kind":"device_authorize","key":signing_key}),
        json!({"key": signing_key}),
    )
    .await;
    client(service, host, Some(&session))
        .call("device_authorize", body)
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
/// A single-use voucher link for `member`: the development registration body
/// (the first members have no earlier member to issue a link) and the redeem
/// request and the link text, all derived from `id`. Present it with [`VoucherCall::voucher_redeem`].
pub fn voucher(_community: &str, member: &str, id: &str, valid_until: u64) -> Value {
    use cvch::link::{Notice, Options, Request, Token};
    let mut entropy = [1u8; 32];
    for (at, byte) in id.bytes().enumerate() {
        entropy[at % 32] ^= byte;
    }
    let (token, _) = Token::issue(entropy, [7; 32], [5; 32]).unwrap();
    let registration = token.registration();
    let valid_for = valid_until.saturating_sub(NOW).max(1);
    Options::new(1, valid_for, None, false).unwrap();
    let notice = Notice {
        member: member.into(),
        nonce: [3; 16],
        handle: None,
        key_package: Vec::new(),
    };
    let request = Request::new(&token, &notice).unwrap();
    json!({
        "seed": {
            "id": registration.id().as_str(),
            "verifier": registration.verifier(),
            "manage_verifier": registration.manage_verifier(),
            "uses": 1,
            "valid_for": valid_for,
            "signoff": null,
        },
        "redeem": {"id": request.id, "secret": request.secret, "notice": request.notice},
        "manage": {"id": registration.id().as_str(), "secret": token.manage().secret_hex().to_string()},
        "link": token.fragment().to_string(),
    })
}
/// Present a [`voucher`]: register its link (a repeat is harmless) and redeem it.
#[allow(async_fn_in_trait)]
pub trait VoucherCall {
    async fn voucher_redeem(&self, voucher: Value) -> cvld::error::Result<Value>;
}
impl VoucherCall for Client {
    async fn voucher_redeem(&self, voucher: Value) -> cvld::error::Result<Value> {
        let _ = self
            .call("development_voucher_link", voucher["seed"].clone())
            .await;
        self.call("voucher_redeem", voucher["redeem"].clone()).await
    }
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

/// Genuine admission before trusted fixture initialization of a preexisting role.
pub async fn admitted_community_member(
    service: &Running,
    scope: &str,
    passport: &cpsd::Passport,
    handle: &str,
) -> Member {
    let host = format!("api.{scope}.{DOMAIN}");
    let member = enrol_community(service, &host, passport).await;
    let subject = passport
        .pseudonym(&cpsd::CommunityId::new(scope).unwrap())
        .to_hex();
    let api = client(service, &host, Some(&member.session));
    api.call("handle_reserve", json!({"handle":handle}))
        .await
        .unwrap();
    api.voucher_redeem(voucher(
        scope,
        &subject,
        handle,
        service.clock.now() + 172_800,
    ))
    .await
    .unwrap();
    let issued = issue_community(service, &host, &member, passport).await;
    assert_eq!(issued.lobby.state, "admitted");
    assert!(issued.credential.is_some());
    member
}

/// Trusted test initialization through the original Register after admission.
/// This is neither signup authority nor a production first-root bootstrap.
pub async fn preexisting_role(service: &Running, scope: &str, subject: &str, role: crgs::Role) {
    let db = crlt::Db::open(crlt::Config::new(
        format!(
            "file://{}",
            service.dir.path().join("community.db").display()
        ),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&cvld::service::community_migrations())
        .await
        .unwrap();
    let register = crgs::Register::new(
        crgs::LibsqlStorage::new(db.community(scope).unwrap()),
        crgs::ReleasePeriod::default(),
    );
    let id = crgs::MemberId::new(subject.as_bytes().to_vec()).unwrap();
    assert!(
        register
            .member(&id)
            .await
            .unwrap()
            .unwrap()
            .handle
            .is_some()
    );
    assert_eq!(register.set_role(&id, role).await.unwrap().role, role);
}

/// Start the genuine isolated Wallet producer with explicit test-owned signing,
/// rulebook, schema and lifetime configuration. No admission or custody grant
/// is inferred; all registration, current-key and certificate calls stay real.
pub async fn configured_wallet(burst: u32) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let config = wallet_config_at(dir.path(), burst, NOW).await;
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let door = cvld::service::Door::global(config, clock.clone())
        .await
        .unwrap();
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

/// Prepare the same explicit Wallet test configuration at the trusted caller
/// clock. A current-time fixture supplies actual SystemClock to Door::global;
/// this data helper starts no owner and grants no registration or custody.
pub async fn wallet_config_at(dir: &Path, burst: u32, now: u64) -> Config {
    let mut config = global_config_at(dir, burst, now).await;
    let mut rules = cmty::cplc::crbk::Rulebook::default();
    rules
        .define(
            "quota",
            cmty::cplc::crbk::Setting {
                value_type: cmty::cplc::crbk::SettingType::Integer,
                nullable: false,
                default: json!(17),
                bounds: cmty::cplc::crbk::Bounds {
                    min: Some(0.into()),
                    max: Some(100.into()),
                },
                lowest_layer: cmty::cplc::crbk::Layer::Community,
                kind: cmty::cplc::crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    let schema = serde_json::from_value(json!({"community":"wallet","version":1,
        "public":[{"id":"consent","label":"Receive invitations?","kind":{"type":"yes_no"},
            "required":true,"filterable":false,"change_preset":"stable","no_contact_details":false}],"private":[]})).unwrap();
    let publication = cgbl::WalletPublicationConfig::new(
        WALLET,
        &format!("https://vault.{WALLET}"),
        rules,
        cmty::cplc::SchemaVersions {
            purpose: cmty::cplc::SchemaVersionsPurpose::SchemaVersionsV1,
            current: 1,
            versions: vec![cmty::cplc::SchemaVersion {
                schema,
                changes: None,
            }],
        },
        std::collections::BTreeSet::new(),
        2 * 86_400,
    )
    .unwrap();
    let seed = dir.join("wallet-seed");
    std::fs::write(&seed, [47; 32]).unwrap();
    let settings = dir.join("wallet-publication.json");
    std::fs::write(&settings, serde_json::to_vec(&publication).unwrap()).unwrap();
    // Test secret: the wallet's confirmation-stamp key (one-day cohort).
    let stamp = dir.join("wallet-stamp-key");
    std::fs::write(&stamp, {
        use cpsd::rand::SeedableRng as _;
        let key = cpsd::StampIssuerKey::generate(
            &mut cpsd::rand::rngs::StdRng::from_seed([53; 32]),
            cpsd::KeyId::new("wallet-stamp-1").unwrap(),
            &cpsd::StampParams::new(86_400).unwrap(),
        )
        .unwrap();
        key.to_secret_bytes()
    }).unwrap();
    config.wallet = Some(cvld::config::WalletConfig {
        signing_seed_file: seed.to_str().unwrap().into(),
        publication_file: settings.to_str().unwrap().into(),
        signer_max_seconds: 100 * 86_400,
        stamp_key_file: Some(stamp.to_str().unwrap().into()),
        stamp_limit: None,
        stamp_period_seconds: None,
        stamp_replay_seconds: None,
    });
    config
}
