#![cfg(feature = "development-gate")]
//! Self-service creation end to end over HTTP: blind token, creation, claim of
//! the first seat, first-admin admission, registry endpoints and termination.
mod support;
use blind_rsa_signatures::{DefaultRng, KeyPairSha384PSSRandomized as KeyPair};
use cvld::{
    address::Reserved,
    api::*,
    creation_token::{self, Issuer, Limits},
    hosts::{Boxed, NoopProvisioner},
    hub::{Factory, Hub, HubParts},
    service::{Clock, CommunityHub, Door},
};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use support::*;

struct TestFactory {
    dir: PathBuf,
    public: GlobalPublic,
    clock: Arc<TestClock>,
}

impl Factory for TestFactory {
    fn open<'a>(
        &'a self,
        address: &'a str,
        seed: [u8; 32],
        plan: Option<cvld::config::CreationPlan>,
        _activation: Option<cvld::accounting::Activation>,
    ) -> Boxed<'a, cvld::error::Result<Door>> {
        Box::pin(async move {
            let mut config = community_config(&self.dir, address, &self.public, 100);
            config.founding_seed = Some(zeroize::Zeroizing::new(seed));
            config.creation = plan;
            config.shared_database = true;
            Door::community(config, self.clock.clone()).await
        })
    }

    fn terms(&self, _now: u64) -> cvld::error::Result<Option<cvld::accounting::AccountingTerms>> {
        Ok(None)
    }

    fn forget(&self, _seed: [u8; 32]) {}
}

fn next_message() -> [u8; 32] {
    static NEXT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(3);
    [NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed); 32]
}

struct Fixture {
    global: Running,
    front: Running,
    hub: Arc<Hub>,
    provisioner: Arc<NoopProvisioner>,
    member: Member,
    passport: cpsd::Passport,
    key: creation_token::PublicKey,
    /// Secret half of the root hold key (offline with Root in production).
    hold_secret: [u8; 32],
    dir_path: PathBuf,
    _dir: tempfile::TempDir,
}

async fn open(db: &std::path::Path) -> crlt::Db {
    crlt::Db::open(crlt::Config::new(format!("file://{}", db.display()), ""))
        .await
        .unwrap()
}

async fn fixture() -> Fixture {
    fixture_with(true).await
}

async fn fixture_with(hold: bool) -> Fixture {
    let global = configured_wallet(100).await;
    let (member, passport, public) = wallet_passport(&global).await;
    let dir = tempfile::tempdir().unwrap();
    let pair = KeyPair::generate(&mut DefaultRng, 2048).unwrap();
    let issuer = Issuer::from_der(&pair.sk.to_der().unwrap()).unwrap();
    let key = creation_token::public_key(&issuer.public_der().unwrap()).unwrap();
    let provisioner = Arc::new(NoopProvisioner::default());
    let (hold_secret, hold_public) = cvld::hold::generate();
    let hub = Hub::new(HubParts {
        global_db: open(&global.dir.path().join("global.db")).await,
        community_db: open(&dir.path().join("community.db")).await,
        issuer,
        limits: Limits {
            per_week: 5,
            per_year: 12,
        },
        provisioner: provisioner.clone(),
        factory: Arc::new(TestFactory {
            dir: dir.path().to_path_buf(),
            public,
            clock: global.clock.clone(),
        }),
        base: DOMAIN.into(),
        reserved: Reserved::new(["reservedname"]),
        clock: global.clock.clone(),
        shell_seconds: 3600,
        master: zeroize::Zeroizing::new(vec![5; 32]),
        hold_key: hold.then_some(hold_public),
    })
    .await
    .unwrap();
    global.door.attach_hub(Arc::new(hub.clone())).unwrap();
    hub.attach_feed(Arc::new(global.door.clone())).unwrap();
    let router = hub.front(&global.door);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let front = Running {
        base,
        door: global.door.clone(),
        clock: global.clock.clone(),
        task,
        dir: tempfile::tempdir().unwrap(),
    };
    Fixture {
        global,
        front,
        hub,
        provisioner,
        member,
        passport,
        key,
        hold_secret,
        dir_path: dir.path().to_path_buf(),
        _dir: dir,
    }
}

impl Fixture {
    /// Whether the platform feed (the wallet's Communities snapshot) states that
    /// the chain with this fingerprint ended.
    async fn ended_in_feed(&self, fingerprint: &str) -> bool {
        let wallet = client(&self.front, WALLET, None);
        let feed: TrustFeed = serde_json::from_value(
            wallet.call("wallet_trust_feed", json!({})).await.unwrap(),
        )
        .unwrap();
        let text = String::from_utf8_lossy(&feed.communities).into_owned();
        text.contains(fingerprint) && text.contains("ended")
    }
    /// A finished token obtained through the HTTP door with the wallet session.
    async fn token(&self) -> Value {
        let wallet = client(&self.front, WALLET, Some(&self.member.session));
        let (pending, blinded) = creation_token::request(&self.key, next_message()).unwrap();
        let response: CreationTokenResponse = serde_json::from_value(
            wallet
                .call("creation_token_issue", json!({ "blinded": blinded }))
                .await
                .unwrap(),
        )
        .unwrap();
        let token = creation_token::finish(&self.key, pending, &response.blind_signature).unwrap();
        json!({"message":token.message,"randomizer":token.randomizer,"signature":token.signature})
    }
    async fn create(&self, address: &str, token: Value) -> cvld::error::Result<CommunityCreated> {
        self.create_with(address, token, json!(["legal", "voucher"]))
            .await
    }
    async fn create_with(
        &self,
        address: &str,
        token: Value,
        gates: Value,
    ) -> cvld::error::Result<CommunityCreated> {
        let anonymous = client(&self.front, WALLET, None);
        anonymous
            .call(
                "community_create",
                json!({"address":address,"token":token,"display_name":"Garden Club","gates":gates}),
            )
            .await
            .map(|value| serde_json::from_value(value).unwrap())
    }
    async fn record(&self, host: &str) -> Option<Value> {
        let response = reqwest::get(format!("{}/registry/by-host?host={host}", self.front.base))
            .await
            .unwrap();
        if response.status() != 200 {
            return None;
        }
        Some(response.json().await.unwrap())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_creation_claim_admission_registry_and_termination() {
    let f = fixture().await;
    let token = f.token().await;
    // Invalid and reserved addresses are refused before the token is touched.
    for bad in ["short", "with-hyphen", "reservedname"] {
        assert!(f.create(bad, token.clone()).await.is_err(), "{bad}");
    }
    // The chosen gates are checked before anything is created: `legal` is required
    // and a gate the platform does not offer is refused.
    for gates in [
        json!([]),
        json!(["voucher"]),
        json!(["legal"]),
        json!(["legal", "bogus"]),
        json!(["legal", "legal"]),
    ] {
        assert!(
            f.create_with("gardenclub", token.clone(), gates.clone())
                .await
                .is_err(),
            "{gates}"
        );
    }
    assert!(f.record(&format!("gardenclub.{DOMAIN}")).await.is_none());
    let created = f.create("gardenclub", token.clone()).await.unwrap();
    assert_eq!(created.community_host, format!("gardenclub.{DOMAIN}"));
    assert_eq!(created.vault_host, format!("vault.gardenclub.{DOMAIN}"));
    assert_eq!(created.fingerprint.len(), 64);
    assert_eq!(
        f.provisioner.calls().iter().filter(|call| call.0).count(),
        1
    );
    // The token is reserved by the shell and cannot create a second community.
    assert!(f.create("otherclub1", token).await.is_err());
    let record = f.record(&created.community_host).await.unwrap();
    assert_eq!(record["state"], "being_created");
    assert_eq!(record["fingerprint"], created.fingerprint);
    assert_eq!(record["id"], created.id);
    assert_eq!(
        f.record(&created.vault_host).await.unwrap()["id"],
        created.id
    );
    // The OHTTP gateway serves LIVE communities only: a shell being created and an
    // unknown host are refused alike.
    let unknown = format!("nobody.{DOMAIN}");
    assert!(!f.hub.serves_host(&created.community_host).await);
    assert!(!f.hub.serves_host(&unknown).await);
    // The creator registers in the new community, claims the seat and is admitted.
    let host = format!("api.gardenclub.{DOMAIN}");
    // The feed carries the founding document from the first revision, so a device
    // that pinned only the fingerprint can verify the key chain.
    let feed: TrustFeed = serde_json::from_value(
        client(&f.front, &host, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    // The display name is part of the signed settings from the first publication.
    assert!(
        feed.settings
            .windows(b"Garden Club".len())
            .any(|window| window == b"Garden Club")
    );
    let genesis = feed
        .genesis
        .expect("the feed publishes the genesis document");
    let verified = csgn::verify_genesis(&genesis).unwrap();
    let digest: String = verified
        .fingerprint()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(digest, created.fingerprint);
    assert_eq!(verified.community(), "gardenclub");
    let creator = enrol_community(&f.front, &host, &f.passport).await;
    let api = client(&f.front, &host, Some(&creator.session));
    let wrong = api
        .call("community_creation_claim", json!({"claim": vec![1u8; 32]}))
        .await;
    assert!(wrong.is_err());
    let claimed: CreationClaimed = serde_json::from_value(
        api.call("community_creation_claim", json!({"claim": created.claim}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claimed.id, created.id);
    api.call("handle_reserve", json!({"handle":"gardener_one"}))
        .await
        .unwrap();
    let subject = f
        .passport
        .pseudonym(&cpsd::CommunityId::new("gardenclub").unwrap())
        .to_hex();
    api.voucher_redeem(voucher(
        "gardenclub",
        &subject,
        "creator-gate",
        f.front.clock.now() + 172_800,
    ))
    .await
    .unwrap();
    let proof = presentation(&f.front, &host, Some(&creator.session), &f.passport).await;
    api.call(
        "credential_issue",
        json!({"presentation":proof,"devices":[creator.signing_key],"creation":claimed.id}),
    )
    .await
    .unwrap();
    assert_eq!(
        f.record(&created.community_host).await.unwrap()["state"],
        "live"
    );
    assert!(f.hub.serves_host(&created.community_host).await);
    assert!(!f.hub.serves_host(&unknown).await);
    // The address is taken while live.
    let again = f.token().await;
    assert!(f.create("gardenclub", again).await.is_err());
    // Root ends it: nothing resolves, the id is listed, the name is blocked.
    let root = enrol(
        &f.global,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    let root_api = client(&f.front, ROOT, Some(&root.session));
    root_api
        .call(
            "community_terminate",
            json!({"address":"gardenclub","reason":"terms","block_name":true}),
        )
        .await
        .unwrap();
    assert!(f.record(&created.community_host).await.is_none());
    // An ended community is refused exactly like a host that never existed.
    assert!(!f.hub.serves_host(&created.community_host).await);
    assert!(!f.hub.serves_host(&unknown).await);
    let finished: Vec<String> = reqwest::get(format!("{}/registry/finished", f.front.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(finished, vec![created.id.clone()]);
    assert_eq!(f.provisioner.calls().last().map(|c| c.0), Some(false));
    let blocked = f.token().await;
    assert!(f.create("gardenclub", blocked).await.is_err());
    // Exactly one root-log row for the termination (not for the creation).
    let log = f.hub.registry().root_log(10).await.unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].address, "gardenclub");
    assert_eq!(log[0].reason, "terms");
    assert!(log[0].block_name && log[0].hold_until.is_none());
    // The platform feed states the end of the chain; a maintenance round repeats
    // the statement if it was lost, without a second entry.
    f.hub.maintain().await.unwrap();
    assert!(f.ended_in_feed(&created.fingerprint).await);
    assert_eq!(f.hub.registry().root_log(10).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_legal_hold_keeps_only_ciphertext_a_root_key_opens() {
    let f = fixture().await;
    let created = f.create("heldclub1", f.token().await).await.unwrap();
    let root = enrol(
        &f.global,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    let root_api = client(&f.front, ROOT, Some(&root.session));
    // A hold belongs to legal orders only.
    let until = f.front.clock.now() + 86_400;
    assert!(
        root_api
            .call(
                "community_terminate",
                json!({"address":"heldclub1","reason":"terms","hold_until":until}),
            )
            .await
            .is_err()
    );
    root_api
        .call(
            "community_terminate",
            json!({"address":"heldclub1","reason":"legal","hold_until":until}),
        )
        .await
        .unwrap();
    // The server scope is empty; the only copy is ciphertext.
    let db = open(&f.dir_path.join("community.db")).await;
    db.migrate(&cvld::service::community_migrations())
        .await
        .unwrap();
    let rows = db
        .community("heldclub1")
        .unwrap()
        .query("SELECT count(*) FROM cvld_genesis", ())
        .await
        .unwrap();
    assert_eq!(rows[0].get_i64(0).unwrap(), 0);
    let id: [u8; 16] = (0..16)
        .map(|i| u8::from_str_radix(&created.id[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let sealed = f.hub.registry().held(id).await.unwrap().unwrap();
    assert!(!sealed.windows(11).any(|w| w == b"cvld_genesi"));
    let opened = cvld::hold::open(&f.hold_secret, &id, &sealed).unwrap();
    assert!(
        String::from_utf8(opened)
            .unwrap()
            .contains("cvld_genesis")
    );
    assert!(cvld::hold::open(&[9; 32], &id, &sealed).is_err());
    assert_eq!(f.hub.registry().root_log(10).await.unwrap().len(), 1);
    // The hold ends: the sealed copy goes and the community is ended.
    f.front.clock.set(until + 1);
    f.hub.maintain().await.unwrap();
    assert!(f.hub.registry().held(id).await.unwrap().is_none());
    assert!(f.ended_in_feed(&created.fingerprint).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_hold_key_a_legal_hold_is_refused_and_nothing_changes() {
    let f = fixture_with(false).await;
    f.create("noholdclub", f.token().await).await.unwrap();
    let root = enrol(
        &f.global,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    let root_api = client(&f.front, ROOT, Some(&root.session));
    let until = f.front.clock.now() + 86_400;
    assert!(
        root_api
            .call(
                "community_terminate",
                json!({"address":"noholdclub","reason":"legal","hold_until":until}),
            )
            .await
            .is_err()
    );
    assert!(f.record(&format!("noholdclub.{DOMAIN}")).await.is_some());
    assert!(f.hub.registry().root_log(10).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_chosen_gates_decide_what_the_lobby_still_asks() {
    let f = fixture().await;
    // The bot fence: `legal` alone (no strong gate, fewer than two medium gates)
    // is refused; `legal` with a voucher is accepted.
    assert!(
        f.create_with("rosegarden", f.token().await, json!(["legal"]))
            .await
            .is_err()
    );
    let with = f.create("withvoucher", f.token().await).await.unwrap();
    let host = format!("api.withvoucher.{DOMAIN}");
    let member = enrol_community(&f.front, &host, &f.passport).await;
    let api = client(&f.front, &host, Some(&member.session));
    api.call("community_creation_claim", json!({"claim": with.claim}))
        .await
        .unwrap();
    let lobby = api.call("lobby", json!({})).await.unwrap();
    let missing = lobby["missing"].to_string();
    assert!(missing.contains("cvch"), "{missing}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_creation_is_repeated_without_a_second_community_or_count() {
    let f = fixture().await;
    let wallet = client(&f.front, WALLET, Some(&f.member.session));
    // The same blinded message again is answered with the same signature and is not
    // counted again (the fixture allows five per week).
    let (pending, blinded) = creation_token::request(&f.key, [90; 32]).unwrap();
    let mut signatures = Vec::new();
    for _ in 0..8 {
        let response: CreationTokenResponse = serde_json::from_value(
            wallet
                .call("creation_token_issue", json!({ "blinded": blinded }))
                .await
                .unwrap(),
        )
        .unwrap();
        signatures.push(response.blind_signature);
    }
    assert!(signatures.windows(2).all(|pair| pair[0] == pair[1]));
    // A device that kept only the pending state finishes the token after a restart.
    let kept = pending.to_state();
    let pending = creation_token::Pending::from_state(kept).unwrap();
    let token = creation_token::finish(&f.key, pending, &signatures[0]).unwrap();
    let token =
        json!({"message":token.message,"randomizer":token.randomizer,"signature":token.signature});
    // The creation is repeated with the same token and address: the same community,
    // the same claim, the same fingerprint, and nothing else is made.
    let first = f.create("restartclub", token.clone()).await.unwrap();
    let again = f.create("restartclub", token.clone()).await.unwrap();
    assert_eq!(again.id, first.id);
    assert_eq!(again.fingerprint, first.fingerprint);
    assert_eq!(again.claim, first.claim);
    assert_eq!(
        f.provisioner.calls().iter().filter(|call| call.0).count(),
        1
    );
    // Another address with the token that is held by a shell is refused.
    let token_again = token.clone();
    assert!(f.create("otherclub1", token).await.is_err());
    // The repeated answer's claim seats the creator.
    let host = format!("api.restartclub.{DOMAIN}");
    let creator = enrol_community(&f.front, &host, &f.passport).await;
    let api = client(&f.front, &host, Some(&creator.session));
    let claimed: CreationClaimed = serde_json::from_value(
        api.call("community_creation_claim", json!({"claim": again.claim}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claimed.id, first.id);
    // A shell lives seven days at least.
    let day = |days: u64| {
        f.front
            .clock
            .0
            .fetch_add(days * 86_400, std::sync::atomic::Ordering::SeqCst)
    };
    day(5);
    // Every resume extends it again.
    let resumed = f.create("restartclub", token_again).await.unwrap();
    assert_eq!(resumed.id, first.id);
    day(5);
    f.hub.sweep().await.unwrap();
    assert_eq!(
        f.record(&first.community_host).await.unwrap()["state"],
        "being_created"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_address_check_names_refusals_the_light_and_free_suggestions() {
    let f = fixture().await;
    let api = client(&f.front, WALLET, None);
    let check = |address: &'static str, name: &'static str| {
        let api = &api;
        async move {
            serde_json::from_value::<AddressAnswer>(
                api.call(
                    "address_check",
                    json!({"address": address, "display_name": name, "suggestions": 3}),
                )
                .await
                .unwrap(),
            )
            .unwrap()
        }
    };
    let free = check("rosegarden", "Rose Garden").await;
    assert!(free.available && free.refusal.is_none());
    assert_eq!(free.light, AddressLight::Green);
    assert!(free.suggestions.len() <= 3);
    let short = check("rose", "Rose Garden").await;
    assert_eq!(short.refusal, Some(AddressRefusal::TooShort));
    assert_eq!(short.light, AddressLight::Red);
    assert!(!short.suggestions.is_empty());
    assert_eq!(
        check("reservedname", "").await.refusal,
        Some(AddressRefusal::Reserved)
    );
    // A taken address is refused and never suggested.
    f.create("rosegarden", f.token().await).await.unwrap();
    let taken = check("rosegarden", "Rosegarden").await;
    assert_eq!(taken.refusal, Some(AddressRefusal::Taken));
    assert!(!taken.suggestions.iter().any(|s| s == "rosegarden"));
}
