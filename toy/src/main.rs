mod fixtures;
mod holder;
mod offline;
mod process;
use cvld::api::*;
use holder::{Member, Wallet, decode};
use process::{Cli, Metrics, Result, Service};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn require(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn refused<T>(result: Result<T>, allowed: &[&str]) -> Result<()> {
    match result {
        Err(e) if allowed.contains(&e.as_str()) => Ok(()),
        Err(e) => Err(format!("unexpected refusal: {e}")),
        Ok(_) => Err("operation unexpectedly succeeded".into()),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    title: String,
    #[serde(default = "one")]
    communities: usize,
    #[serde(default = "burst")]
    burst: u32,
    steps: Vec<Step>,
}
fn one() -> usize {
    1
}
fn burst() -> u32 {
    10000
}
#[derive(Deserialize)]
#[serde(tag = "do", rename_all = "snake_case", deny_unknown_fields)]
enum Step {
    Wallet {
        name: String,
    },
    Join {
        wallet: String,
        member: String,
        community: usize,
    },
    Unlinkable {
        first: String,
        second: String,
    },
    Handle {
        member: String,
        value: String,
    },
    Lobby {
        member: String,
        state: Option<String>,
        missing: Option<String>,
        warnings: Option<bool>,
    },
    Voucher {
        member: String,
    },
    Issue {
        member: String,
        state: String,
    },
    Policy {
        community: usize,
        voucher: bool,
    },
    Withdraw {
        member: String,
    },
    Expire {
        member: String,
    },
    NoReturn {
        member: String,
    },
    LoseAll {
        member: String,
    },
    SecondDevice {
        member: String,
    },
    Force {
        community: usize,
    },
    Suspend {
        wallet: String,
    },
    RenewalBlocked {
        member: String,
    },
    Throttle,
    Offline {
        member: String,
    },
}
struct Joined {
    community: usize,
    wallet: String,
    member: Member,
    credential: Option<Vec<u8>>,
}
struct Community {
    service: Service,
    name: String,
    verifier: offline::Verifier,
    admin: Option<Member>,
    root: Option<Member>,
}
struct World {
    global: Service,
    communities: Vec<Community>,
    wallets: BTreeMap<String, Wallet>,
    members: BTreeMap<String, Joined>,
    now: u64,
    clock: PathBuf,
    metrics: Arc<Mutex<Metrics>>,
    _dir: tempfile::TempDir,
    blocked: Vec<String>,
}
impl World {
    async fn new(bin: &Path, count: usize, burst: u32, remote: bool) -> Result<Self> {
        let dir = tempfile::tempdir().map_err(|_| "temporary directory")?;
        let clock = dir.path().join("clock");
        let now = if remote {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        } else {
            fixtures::NOW
        };
        process::clock(&clock, now);
        let metrics = Arc::new(Mutex::new(Metrics::default()));
        let global_dir = dir.path().join("global");
        fs::create_dir(&global_dir).map_err(|_| "global directory")?;
        fixtures::global(&global_dir, process::port(), burst, now).await;
        if remote {
            let url = std::env::var("TURSO_URL").map_err(|_| "TURSO_URL required")?;
            let token = std::env::var("TURSO_TOKEN").map_err(|_| "TURSO_TOKEN required")?;
            require(
                !url.is_empty() && !token.is_empty(),
                "both Turso values must be nonempty",
            )?;
            let path = global_dir.join("config.json");
            let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            config["database_url"] = json!(url);
            let token_path = global_dir.join("database-token");
            fs::write(&token_path, token).unwrap();
            config["database_token_file"] = json!(token_path);
            fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
        }
        let global = Service::start(
            bin,
            &global_dir,
            "global",
            fixtures::WALLET.into(),
            &clock,
            metrics.clone(),
        )?;
        let public: GlobalPublic = decode(global.initial.clone())?;
        let mut communities = Vec::new();
        for index in 0..count {
            let name = format!("community{index}");
            let community_dir = dir.path().join(&name);
            fs::create_dir(&community_dir).map_err(|_| "community directory")?;
            fixtures::community(&community_dir, process::port(), &name, &public, burst);
            let service = Service::start(
                bin,
                &community_dir,
                "community",
                format!("api.{name}.{}", fixtures::DOMAIN),
                &clock,
                metrics.clone(),
            )?;
            let feed: TrustFeed = decode(service.initial.clone())?;
            let ring = csgn::KeyRing::from_cbor(&feed.key_ring).map_err(|_| "community ring")?;
            let mut verifier = offline::Verifier::new(&name, ring);
            verifier.update(&feed, now)?;
            communities.push(Community {
                service,
                name,
                verifier,
                admin: None,
                root: None,
            });
        }
        // Startup and readiness probes are excluded from action measurements.
        metrics.lock().unwrap().actions.clear();
        Ok(Self {
            global,
            communities,
            wallets: BTreeMap::new(),
            members: BTreeMap::new(),
            now,
            clock,
            metrics,
            _dir: dir,
            blocked: Vec::new(),
        })
    }
    fn advance(&mut self, seconds: u64) {
        self.now += seconds;
        process::clock(&self.clock, self.now);
    }
    fn cli(&self, member: &str) -> (&Cli, &Joined) {
        let joined = &self.members[member];
        (&self.communities[joined.community].service.cli, joined)
    }
    fn lobby(&self, member: &str) -> Result<Lobby> {
        let (cli, j) = self.cli(member);
        decode(cli.call(Some(&j.member.session), "lobby", json!({}))?)
    }
    fn presentation(&self, member: &str) -> Result<PresentationInput> {
        let (cli, j) = self.cli(member);
        let community = &self.communities[j.community];
        holder::presentation(
            cli,
            Some(&j.member.session),
            &self.wallets[&j.wallet].passport,
            &community.verifier.ring,
            &community.name,
            self.now,
        )
    }
    fn issue(&self, member: &str) -> Result<CredentialResponse> {
        let proof = self.presentation(member)?;
        let (cli, j) = self.cli(member);
        decode(cli.call(
            Some(&j.member.session),
            "credential_issue",
            json!({"presentation":proof,"devices":[j.member.device]}),
        )?)
    }
    fn feed(&self, index: usize) -> Result<TrustFeed> {
        decode(
            self.communities[index]
                .service
                .cli
                .call(None, "trust_feed", json!({}))?,
        )
    }
    fn voucher(&self, name: &str) -> Result<()> {
        let lobby = self.lobby(name)?;
        let (cli, j) = self.cli(name);
        let id = format!("voucher-{}", self.now);
        let body = holder::voucher(
            &self.communities[j.community].name,
            &lobby.member_id,
            &format!("{id}-{name}"),
            self.now,
        );
        cli.call(Some(&j.member.session), "gate_voucher", body.clone())?;
        refused(
            cli.call(Some(&j.member.session), "gate_voucher", body),
            &["operation refused"],
        )
    }
    fn admin(&mut self, index: usize) -> Result<(Cli, String)> {
        let c = &mut self.communities[index];
        let cli = c
            .service
            .cli
            .host(&format!("api.admin.{}.{}", c.name, fixtures::DOMAIN));
        if c.admin.is_none() {
            c.admin = Some(holder::register(
                &cli,
                Some("synthetic-admin-enrolment-capability"),
                None,
            )?);
        }
        Ok((cli, c.admin.as_ref().unwrap().session.clone()))
    }
    fn refresh_global(&mut self) -> Result<()> {
        let public: GlobalPublic =
            decode(self.global.cli.call(None, "global_public", json!({}))?)?;
        for c in &self.communities {
            // This is public operator configuration distribution, never a member API bypass.
            let next = c.service.dir.join("global-status.next");
            fs::write(&next, &public.status).map_err(|_| "public status update")?;
            fs::rename(next, c.service.dir.join("global-status"))
                .map_err(|_| "public status replace")?;
        }
        Ok(())
    }
    fn step(&mut self, step: Step) -> Result<&'static str> {
        match step {
            Step::Wallet { name } => {
                require(!self.wallets.contains_key(&name), "duplicate wallet alias")?;
                self.wallets.insert(name, holder::wallet(&self.global.cli)?);
                Ok("software passkey and blind-issued wallet created")
            }
            Step::Join {
                wallet,
                member,
                community,
            } => {
                let c = &self.communities[community];
                let passport = &self.wallets[&wallet].passport;
                let proof = holder::presentation(
                    &c.service.cli,
                    None,
                    passport,
                    &c.verifier.ring,
                    &c.name,
                    self.now,
                )?;
                let account = holder::register(&c.service.cli, None, Some(proof))?;
                require(
                    !self.members.contains_key(&member),
                    "duplicate member alias",
                )?;
                self.members.insert(
                    member,
                    Joined {
                        community,
                        wallet,
                        member: account,
                        credential: None,
                    },
                );
                Ok("community passkey registered; lobby reached")
            }
            Step::Unlinkable { first, second } => {
                let a = self.lobby(&first)?;
                let b = self.lobby(&second)?;
                let ja = &self.members[&first];
                let jb = &self.members[&second];
                require(
                    ja.wallet == jb.wallet && ja.community != jb.community,
                    "unlinkability scenario setup",
                )?;
                require(
                    a.member_id != b.member_id
                        && ja.member.user != jb.member.user
                        && ja.member.device != jb.member.device,
                    "community identities must differ",
                )?;
                for (j, lobby) in [(ja, &a), (jb, &b)] {
                    let id = cpsd::CommunityId::new(&self.communities[j.community].name)
                        .map_err(|_| "community id")?;
                    require(
                        lobby.member_id == self.wallets[&j.wallet].passport.pseudonym(&id).to_hex(),
                        "holder pseudonym mismatch",
                    )?;
                    require(
                        lobby.member_id != self.wallets[&j.wallet].member.user,
                        "global identity leaked",
                    )?;
                }
                refused(
                    self.communities[jb.community].service.cli.call(
                        Some(&ja.member.session),
                        "lobby",
                        json!({}),
                    ),
                    &["authentication required"],
                )?;
                Ok(
                    "same wallet yields distinct pseudonyms, accounts and device keys; foreign session refused",
                )
            }
            Step::Handle { member, value } => {
                let (cli, j) = self.cli(&member);
                cli.call(
                    Some(&j.member.session),
                    "handle_reserve",
                    json!({"handle":value}),
                )?;
                require(
                    self.lobby(&member)?.handle.as_deref() == Some(value.as_str()),
                    "handle was not reserved",
                )?;
                Ok("handle reserved")
            }
            Step::Lobby {
                member,
                state,
                missing,
                warnings,
            } => {
                let lobby = self.lobby(&member)?;
                if let Some(state) = state {
                    require(lobby.state == state, "unexpected lobby state")?;
                }
                if let Some(gate) = missing {
                    require(
                        lobby.missing.to_string().contains(&gate),
                        "missing gate absent from lobby",
                    )?;
                }
                if warnings == Some(true) {
                    require(
                        lobby
                            .warnings
                            .iter()
                            .any(|w| matches!(w, LobbyWarning::RegistrationExpires { .. })),
                        "registration expiry warning missing",
                    )?;
                    require(
                        lobby
                            .warnings
                            .iter()
                            .any(|w| matches!(w, LobbyWarning::AddSecondDeviceOrSyncedPasskey)),
                        "second device warning missing",
                    )?;
                }
                Ok("lobby state, missing requirements and requested warnings asserted")
            }
            Step::Voucher { member } => {
                self.voucher(&member)?;
                Ok("member-bound voucher accepted; replay refused")
            }
            Step::Issue { member, state } => {
                let issued = self.issue(&member)?;
                require(issued.lobby.state == state, "unexpected admission state")?;
                require(
                    issued.credential.is_some() == (state == "admitted"),
                    "credential presence disagrees with admission",
                )?;
                let index = self.members[&member].community;
                let feed = self.feed(index)?;
                self.communities[index].verifier.update(&feed, self.now)?;
                if let Some(bytes) = &issued.credential {
                    let credential = self.communities[index]
                        .verifier
                        .credential(bytes, self.now)?;
                    require(
                        credential.member == issued.lobby.member_id,
                        "credential holder mismatch",
                    )?;
                }
                self.members.get_mut(&member).unwrap().credential = issued.credential;
                Ok("credential result and enrolment state asserted")
            }
            Step::Policy { community, voucher } => {
                let before = self.feed(community)?;
                let mut requirements =
                    vec![json!({"gate":"development","level":"global","provider":null})];
                if voucher {
                    requirements.push(json!({"gate":"cvch","level":"community","provider":null}));
                }
                let policy = cmnt::cplc::crbk::ActionPolicy {
                    all_of: serde_json::from_value(json!(requirements))
                        .map_err(|_| "policy requirements")?,
                    ..Default::default()
                };
                let (cli, session) = self.admin(community)?;
                self.advance(1);
                let after: TrustFeed = decode(cli.call(Some(&session),"setting_set",json!({
                    "key":cmnt::cplc::crbk::action_key(cmnt::ADMISSION_ACTION),"value":policy,"inherit":false,"effective_at":self.now
                }))?)?;
                require(
                    after.policy_epoch > before.policy_epoch
                        && after.revision > before.revision
                        && after.settings != before.settings,
                    "policy publication did not advance",
                )?;
                self.communities[community]
                    .verifier
                    .update(&after, self.now)?;
                for joined in self.members.values().filter(|j| j.community == community) {
                    if let Some(bytes) = &joined.credential {
                        require(
                            self.communities[community]
                                .verifier
                                .credential(bytes, self.now)
                                .is_err(),
                            "old epoch credential accepted",
                        )?;
                    }
                }
                require(
                    self.communities[community]
                        .verifier
                        .update(&before, self.now)
                        .is_err(),
                    "trust rollback accepted",
                )?;
                Ok(
                    "admin policy and signed snapshot advanced; stale credentials and rollback refused",
                )
            }
            Step::Withdraw { member } => {
                let proof = self.presentation(&member)?;
                let (cli, j) = self.cli(&member);
                let response: CredentialResponse = decode(cli.call(Some(&j.member.session),"gate_withdraw",json!({
                    "gate":"cvch","provider":"sponsor","credential":{"presentation":proof,"devices":[j.member.device]}
                }))?)?;
                require(
                    response.credential.is_none() && response.lobby.state == "lapsed",
                    "red gate failed to lapse member",
                )?;
                let index = j.community;
                let feed = self.feed(index)?;
                self.communities[index].verifier.update(&feed, self.now)?;
                if let Some(bytes) = &self.members[&member].credential {
                    require(
                        self.communities[index]
                            .verifier
                            .credential(bytes, self.now)
                            .is_err(),
                        "lapsed credential still accepted",
                    )?;
                }
                Ok("red gate lapses membership and invalidates the prior credential")
            }
            Step::Expire { member } => {
                let lobby = self.lobby(&member)?;
                let deadline = lobby
                    .warnings
                    .iter()
                    .find_map(|w| match w {
                        LobbyWarning::RegistrationExpires { deadline } => Some(*deadline as u64),
                        _ => None,
                    })
                    .ok_or("expiry warning missing")?;
                let handle = lobby
                    .handle
                    .ok_or("expiry scenario needs a reserved handle")?;
                self.advance(deadline.saturating_sub(self.now));
                // Real process restart invokes normal maintenance at the controlled time.
                self.global.restart()?;
                self.refresh_global()?;
                let index = self.members[&member].community;
                self.communities[index].service.restart()?;
                let deadline = Instant::now() + Duration::from_secs(35);
                loop {
                    let available: Available = decode(self.communities[index].service.cli.call(
                        None,
                        "handle_available",
                        json!({"handle":handle}),
                    )?)?;
                    if available.available {
                        break;
                    }
                    require(
                        Instant::now() < deadline,
                        "expired registration kept its handle",
                    )?;
                    std::thread::sleep(Duration::from_millis(100));
                }
                Ok("registration deadline reached; normal maintenance freed the pending handle")
            }
            Step::NoReturn { member } => {
                let j = &self.members[&member];
                let c = &self.communities[j.community];
                let proof = holder::presentation(
                    &c.service.cli,
                    None,
                    &self.wallets[&j.wallet].passport,
                    &c.verifier.ring,
                    &c.name,
                    self.now,
                )?;
                refused(
                    c.service
                        .cli
                        .call(None, "register_begin", json!({"passport":proof})),
                    &["operation refused"],
                )?;
                Ok("fresh proof of the same pseudonym cannot register again: NO RETURN")
            }
            Step::LoseAll { member } => {
                let (cli, j) = self.cli(&member);
                cli.call(
                    Some(&j.member.session),
                    "passkey_revoke",
                    json!({"credential":j.member.credential}),
                )?;
                refused(
                    cli.call(Some(&j.member.session), "lobby", json!({})),
                    &["authentication required"],
                )?;
                let index = j.community;
                let feed = self.feed(index)?;
                self.communities[index].verifier.update(&feed, self.now)?;
                if let Some(bytes) = &self.members[&member].credential {
                    require(
                        self.communities[index]
                            .verifier
                            .credential(bytes, self.now)
                            .is_err(),
                        "released credential accepted",
                    )?;
                }
                Ok("last passkey revoked; session and prior credential refused")
            }
            Step::SecondDevice { member } => {
                let (cli, j) = self.cli(&member);
                refused(
                    cli.call(Some(&j.member.session), "register_begin", json!({})),
                    &["invalid request"],
                )?;
                let c = &self.communities[j.community];
                let proof = holder::presentation(
                    cli,
                    None,
                    &self.wallets[&j.wallet].passport,
                    &c.verifier.ring,
                    &c.name,
                    self.now,
                )?;
                refused(
                    cli.call(
                        Some(&j.member.session),
                        "register_begin",
                        json!({"passport":proof}),
                    ),
                    &["operation refused"],
                )?;
                self.blocked.push("Second-device enrolment has no public action or membership-facade capability; surviving-device access cannot yet be proved.".into());
                Ok("BLOCKED: second-device enrolment is unavailable through the public CLI")
            }
            Step::Force { community } => {
                let (admin, session) = self.admin(community)?;
                let c = &mut self.communities[community];
                c.root = Some(holder::root(&c.service.cli, false)?);
                let root = c.service.cli.host(fixtures::ROOT);
                let root_session = c.root.as_ref().unwrap().session.clone();
                self.advance(1);
                let request = json!({"setting":{"key":"quota","value":3,"inherit":false,"effective_at":self.now},"force":true});
                refused(
                    admin.call(Some(&session), "platform_set", request.clone()),
                    &["action forbidden"],
                )?;
                root.call(Some(&root_session), "platform_set", request)?;
                self.advance(1);
                let feed: TrustFeed = decode(admin.call(
                    Some(&session),
                    "setting_set",
                    json!({"key":"quota","value":8,"inherit":false,"effective_at":self.now}),
                )?)?;
                let settings = self.communities[community]
                    .verifier
                    .update(&feed, self.now)?;
                require(settings["quota"] == 3, "community bypassed root force")?;
                Ok("root force wins over community override; admin cannot force")
            }
            Step::Suspend { wallet } => {
                let root = holder::root(&self.global.cli, true)?;
                let cli = self.global.cli.host(fixtures::ROOT);
                let user = &self.wallets[&wallet].member.user;
                cli.call(Some(&root.session), "global_warn", json!({"user":user}))?;
                cli.call(
                    Some(&root.session),
                    "global_suspend",
                    json!({"user":user,"until":(self.now/86400+3)*86400}),
                )?;
                refused(
                    self.global.cli.call(
                        Some(&self.wallets[&wallet].member.session),
                        "passport_challenge",
                        json!({}),
                    ),
                    &["operation refused"],
                )?;
                self.refresh_global()?;
                Ok(
                    "warned wallet suspended; passport renewal refused; signed public epoch distributed",
                )
            }
            Step::RenewalBlocked { member } => {
                refused(
                    self.issue(&member),
                    &["wallet refuses presentation", "operation refused"],
                )?;
                Ok("community renewal refused with the suspended wallet's passport")
            }
            Step::Throttle => {
                let cli = &self.communities[0].service.cli;
                for (action, body) in [
                    ("register_begin", json!({})),
                    ("handle_available", json!({"handle":"unused_handle"})),
                ] {
                    let first = cli.call(None, action, body.clone());
                    require(
                        first
                            .as_ref()
                            .err()
                            .is_none_or(|e| e != "request throttled"),
                        "quota unexpectedly exhausted",
                    )?;
                    refused(cli.call(None, action, body), &["request throttled"])?;
                }
                Ok("registration and handle-check aggregate quotas enforced")
            }
            Step::Offline { member } => {
                let index = self.members[&member].community;
                let feed = self.feed(index)?;
                self.communities[index].verifier.update(&feed, self.now)?;
                let credential = self.members[&member]
                    .credential
                    .as_ref()
                    .ok_or("offline scenario needs a credential")?
                    .clone();
                for c in &mut self.communities {
                    c.service.stop();
                }
                self.global.stop();
                let verifier = &self.communities[index].verifier;
                verifier.credential(&credential, self.now)?;
                let mut damaged = credential.clone();
                let end = damaged.len() - 1;
                damaged[end] ^= 1;
                require(
                    verifier.credential(&damaged, self.now).is_err(),
                    "tampered credential accepted",
                )?;
                require(
                    verifier.credential(&credential, self.now + 86400).is_err(),
                    "expired new-member credential accepted while snapshots remain fresh",
                )?;
                require(
                    verifier
                        .credential(&credential, self.now + 40 * 86400)
                        .is_err(),
                    "expired credential or trust accepted",
                )?;
                let mut foreign = offline::Verifier::new("other-community", verifier.ring.clone());
                require(
                    foreign.update(&feed, self.now).is_err(),
                    "foreign-community trust accepted",
                )?;
                let mut substituted = feed.clone();
                substituted.schema_versions = feed.schema.clone();
                require(
                    self.communities[index]
                        .verifier
                        .update(&substituted, self.now)
                        .is_err(),
                    "schema accepted as schema history",
                )?;
                let mut damaged_feed = feed.clone();
                let end = damaged_feed.settings.len() - 1;
                damaged_feed.settings[end] ^= 1;
                require(
                    self.communities[index]
                        .verifier
                        .update(&damaged_feed, self.now)
                        .is_err(),
                    "tampered settings accepted",
                )?;
                Ok(
                    "services stopped; offline credential accepted; tamper, expiry and foreign scope refused",
                )
            }
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("toy failed: {error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("scenarios");
    let bin =
        PathBuf::from(std::env::var("CVLD_BIN").unwrap_or_else(|_| "target/debug/cvld".into()))
            .canonicalize()
            .map_err(|_| "set CVLD_BIN to the development binary")?;
    let report_dir =
        PathBuf::from(std::env::var("TOY_REPORT_DIR").unwrap_or_else(|_| "toy/reports".into()));
    fs::create_dir_all(&report_dir).map_err(|_| "report directory")?;
    match mode {
        "scenarios" => {
            let mut paths: Vec<PathBuf> = if args.len() > 1 {
                args[1..].iter().map(PathBuf::from).collect()
            } else {
                fs::read_dir("toy/scenarios")
                    .map_err(|_| "scenario directory")?
                    .map(|e| e.unwrap().path())
                    .filter(|p| p.extension().is_some_and(|e| e == "json"))
                    .collect()
            };
            paths.sort();
            require(!paths.is_empty(), "no scenarios selected")?;
            let mut results = Vec::new();
            for path in paths {
                let scenario: Scenario =
                    serde_json::from_slice(&fs::read(path).map_err(|_| "scenario file")?)
                        .map_err(|_| "invalid scenario script")?;
                println!("SCENARIO {}", scenario.title);
                let mut world =
                    World::new(&bin, scenario.communities, scenario.burst, false).await?;
                for (index, step) in scenario.steps.into_iter().enumerate() {
                    let line = world
                        .step(step)
                        .map_err(|e| format!("{} step {}: {e}", scenario.title, index + 1))?;
                    println!("  {}. {line}", index + 1);
                }
                let status = if world.blocked.is_empty() {
                    "PASS"
                } else {
                    "BLOCKED"
                };
                println!("{status}: {}", scenario.title);
                results.push(json!({"scenario":scenario.title,"status":status,"blockers":world.blocked,"metrics":world.metrics.lock().unwrap().report()}));
            }
            fs::write(
                report_dir.join("scenarios.json"),
                serde_json::to_vec_pretty(&results).unwrap(),
            )
            .map_err(|_| "write scenario report")?;
            println!(
                "Scenarios: {} passed, {} blocked",
                results.iter().filter(|r| r["status"] == "PASS").count(),
                results.iter().filter(|r| r["status"] == "BLOCKED").count()
            );
        }
        "scale" => scale(&bin, &report_dir, false).await?,
        "turso" => {
            if ["TURSO_URL", "TURSO_TOKEN"]
                .iter()
                .any(|key| std::env::var(key).unwrap_or_default().is_empty())
            {
                println!("SKIP: optional Turso run needs both TURSO_URL and TURSO_TOKEN");
            } else {
                // A single supplied disposable database can host only the global service.
                let world = World::new(&bin, 1, 10000, true).await?;
                holder::wallet(&world.global.cli)?;
                println!(
                    "PASS: optional Turso global-service passkey, gate and blind passport round trip"
                );
            }
        }
        _ => return Err("usage: cvld-toy [scenarios [files...] | scale | turso]".into()),
    }
    Ok(())
}
async fn scale(bin: &Path, reports: &Path, remote: bool) -> Result<()> {
    let mut world = World::new(bin, 5, 10000, remote).await?;
    let start = Instant::now();
    for index in 0..200 {
        let name = format!("member{index:04}");
        world.step(Step::Wallet { name: name.clone() })?;
        // Each of 200 holders joins each of 5 isolated communities: 1,000 admissions.
        for community in 0..5 {
            let alias = format!("{name}-{community}");
            world.step(Step::Join {
                wallet: name.clone(),
                member: alias.clone(),
                community,
            })?;
            world.step(Step::Handle {
                member: alias.clone(),
                value: name.clone(),
            })?;
            world.step(Step::Voucher {
                member: alias.clone(),
            })?;
            world.step(Step::Issue {
                member: alias.clone(),
                state: "admitted".into(),
            })?;
            // A fresh login/lobby observes the populated database as real clients do.
            let j = world.members.get_mut(&alias).unwrap();
            holder::login(&world.communities[community].service.cli, &mut j.member)?;
            world.lobby(&alias)?;
        }
        if (index + 1) % 20 == 0 {
            println!(
                "SCALE: {} / 200 wallets; {} / 1000 admissions",
                index + 1,
                (index + 1) * 5
            );
        }
    }
    let metrics = world.metrics.lock().unwrap().report();
    require(
        metrics
            .as_object()
            .unwrap()
            .values()
            .any(|m| m["rows_read"].as_u64().unwrap_or(0) > 0),
        "row meter inactive; refusing a zero-cost report",
    )?;
    for (action, metric) in metrics.as_object().unwrap() {
        println!(
            "{action}: n={} p50={:.1}ms p95={:.1}ms p99={:.1}ms rows={}/{} {}",
            metric["count"],
            metric["p50_ms"].as_f64().unwrap(),
            metric["p95_ms"].as_f64().unwrap(),
            metric["p99_ms"].as_f64().unwrap(),
            metric["rows_read"],
            metric["rows_returned"],
            metric["flag"].as_str().unwrap()
        );
    }
    fs::write(reports.join("scale.json"),serde_json::to_vec_pretty(&json!({"wallets":200,"communities":5,"admissions":1000,
        "elapsed_seconds":start.elapsed().as_secs_f64(),"metrics":metrics,
        "measurement":"Sequential public CLI wall time, including process startup. Actual libSQL rows read and SQL result rows; EXPLAIN excluded. Concurrent maintenance is conservatively included."})).unwrap()).map_err(|_| "write scale report")?;
    Ok(())
}
