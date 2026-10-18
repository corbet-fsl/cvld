use super::*;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use cmty::cplc::{self, crbk};
use cvld::{accounting::AccountConfig, config::CommunityConfig};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicU64,
};
use tower::ServiceExt;

pub(super) struct Fixture {
    pub config: CommunityConfig,
    pub context_deadline: u64,
    pub epoch: u64,
    _directory: tempfile::TempDir,
    _global: support::Running,
}
/// The three native-account inputs. An explicit environment variable wins (CI exports all three
/// from `tools/g5-account-config.py`); otherwise the same reviewed generator runs once per target
/// directory for community alpha at the suite's fixed NOW and its output is cached under
/// `CARGO_TARGET_TMPDIR`. The retained artifact root is `CVLD_G5_RETAINED`, else the local journey
/// capture `~/agents/scratch/e2e/retained/release-artifacts` when present, else the generator's own
/// CI default (`ARTIFACT_ROOT`, `CI_CACHE_ROOT`, `CARGO_HOME`).
struct Inputs {
    config: PathBuf,
    probe: PathBuf,
    sha256: String,
}
fn inputs() -> &'static Inputs {
    static INPUTS: std::sync::OnceLock<Inputs> = std::sync::OnceLock::new();
    INPUTS.get_or_init(|| {
        let config = std::env::var_os("CVLD_G5_ACCOUNT_CONFIG");
        let probe = std::env::var_os("CVLD_ALPHA_ACTIVATION_PROBE");
        let sha256 = std::env::var("CVLD_ALPHA_ACTIVATION_SHA256");
        if let (Some(config), Some(probe), Ok(sha256)) = (config, probe, sha256) {
            return Inputs {
                config: config.into(),
                probe: probe.into(),
                sha256,
            };
        }
        let cache = Path::new(env!("CARGO_TARGET_TMPDIR")).join("g5-alpha-in-place");
        if !cache.join("probe.sha256").is_file() {
            generate(&cache);
        }
        Inputs {
            config: cache.join("account-config.json"),
            probe: cache.join("activation-probe.json"),
            sha256: std::fs::read_to_string(cache.join("probe.sha256")).unwrap(),
        }
    })
}
fn generate(cache: &Path) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    // The generated configuration embeds absolute paths below --out, so it is generated in place.
    // One process generates (the lock directory); concurrent ones wait for the completeness mark.
    let mark = cache.join("probe.sha256");
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    if std::fs::create_dir(cache.with_extension("lock")).is_err() {
        let start = std::time::Instant::now();
        while !mark.is_file() {
            assert!(start.elapsed().as_secs() < 300, "G5 fixture generation did not finish");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        return;
    }
    let mut command = std::process::Command::new("python3");
    command
        .args(["-B", "tools/g5-account-config.py", "--community", "alpha"])
        .args(["--exports", "--now", &support::NOW.to_string(), "--out"])
        .arg(cache)
        .current_dir(root);
    let retained = std::env::var_os("CVLD_G5_RETAINED").map(PathBuf::from).or_else(|| {
        let home = std::env::var_os("HOME")?;
        let local = Path::new(&home).join("agents/scratch/e2e/retained/release-artifacts");
        local.is_dir().then_some(local)
    });
    if let Some(retained) = retained {
        command.arg("--retained").arg(retained);
    }
    let output = command.output().expect("python3 runs the G5 generator");
    assert!(
        output.status.success(),
        "G5 account configuration generator failed (set CVLD_G5_RETAINED or the three CVLD_* variables): {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The pin comes from the generator's output, as in CI, written last as the completeness mark.
    let stdout = String::from_utf8(output.stdout).unwrap();
    let sha256 = stdout
        .lines()
        .find_map(|l| l.strip_prefix("export CVLD_ALPHA_ACTIVATION_SHA256="))
        .expect("generator exports the probe digest");
    std::fs::write(mark, sha256).unwrap();
}
fn required_file(path: &Path, maximum: usize) -> Vec<u8> {
    assert!(path.is_absolute());
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() <= maximum);
    bytes
}
fn write(directory: &Path, name: &str, bytes: &[u8]) -> String {
    let path = directory.join(name);
    std::fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_owned()
}
fn hex(bytes: &str) -> Vec<u8> {
    assert!(bytes.len().is_multiple_of(2));
    bytes
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
impl Fixture {
    /// The configuration is a plain serde value; an exact copy is its own round trip.
    pub fn duplicate_config(&self) -> CommunityConfig {
        serde_json::from_value(serde_json::to_value(&self.config).unwrap()).unwrap()
    }
    pub async fn new() -> Self {
        // This is operator fixture configuration of the ACTUAL application
        // types and pins. It is not part of a public member/provider DTO.
        let mut account: AccountConfig =
            serde_json::from_slice(&required_file(&inputs().config, 1024 * 1024))
                .expect("explicit native artifact/worker/key configuration required");
        let probe_bytes = required_file(&inputs().probe, 4 * 1024 * 1024);
        // The expected retained-byte pin is supplied independently of the
        // downloaded probe. Actual native verification remains mandatory.
        let expected = inputs().sha256.clone();
        // Canonical base64url SHA-256, using the original encoding owner.
        assert_eq!(expected, czkp::digest(&probe_bytes));
        let probe: Value = serde_json::from_slice(&probe_bytes).unwrap();
        assert_eq!(probe["version"], 1);
        assert_eq!(probe["use"], "alpha-startup-activation-probe");
        assert_eq!(probe["authority"], "none");
        assert_eq!(probe["communityId"], "alpha");
        assert_eq!(probe["configuration"]["observation"], NOW);
        assert_eq!(probe["configuration"]["policyEpoch"], 4);
        assert_eq!(probe["configuration"]["rulebook"]["periodSeconds"], 86_400);
        assert_eq!(probe["configuration"]["rulebook"]["quota"], 4);
        assert_eq!(probe["policy"], probe["configuration"]["accountPolicy"]);
        assert_eq!(
            probe["extension"],
            probe["configuration"]["extensionPolicy"]
        );
        let policy: cblc::accounting::AccountPolicy =
            serde_json::from_value(probe["policy"].clone()).unwrap();
        let extension: cblc::extensions::ExtensionPolicy =
            serde_json::from_value(probe["extension"].clone()).unwrap();
        assert_eq!(policy.policy_valid_from, NOW - 1);
        assert_eq!(policy.policy_valid_until, NOW + 86_400);
        assert_eq!(policy.initial_credit, 3);
        assert_eq!(policy.maximum_available, 3);
        assert_eq!(extension.minimum_deposit_batch, 2);
        let statement: cblc::accounting::AccountStatement =
            serde_json::from_value(probe["activation"]["account"].clone()).unwrap();
        assert_eq!(statement.now, NOW);
        assert!(statement.genesis);
        assert_eq!(statement.policy, policy);
        let proof = hex(probe["activation"]["proof"].as_str().unwrap());
        assert!(!proof.is_empty());
        // Scope/policy/witness bytes are never rewritten for this factory.
        assert_eq!(
            hex(probe["manifestSha256"].as_str().unwrap()),
            account.extension_artifacts.manifest_sha256
        );
        assert_eq!(account.period_key, "record/window");
        assert_eq!(account.settlement.quota_key, "outcomes/allowance");
        assert_eq!(
            account.admission_policy_digest,
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"
        );
        let directory = tempfile::tempdir().unwrap();
        let ledger = cblc::AccountLedgerPolicy {
            account: policy,
            max_authorization_seconds: 100,
            max_proof_bytes: 4 * 1024 * 1024,
            checkpoint_period_seconds: 86_400,
        };
        account.ledger_policy_file = write(
            directory.path(),
            "ledger-policy.json",
            &serde_json::to_vec(&ledger).unwrap(),
        );
        account.extension_policy_file = write(
            directory.path(),
            "extension-policy.json",
            &serde_json::to_vec(&extension).unwrap(),
        );
        account.activation_statement_file = write(
            directory.path(),
            "activation-statement.json",
            &serde_json::to_vec(&statement).unwrap(),
        );
        account.activation_proof_file = write(directory.path(), "activation-proof", &proof);
        let epoch: Value =
            serde_json::from_slice(&std::fs::read(&account.settlement.epoch_file).unwrap())
                .unwrap();
        assert_eq!(epoch["community"], "alpha");
        assert_eq!(epoch["epoch"], NOW / 86_400);
        let context_deadline = epoch["valid_until"].as_u64().unwrap() / 1000;
        assert_eq!(context_deadline, (NOW / 86_400 + 1) * 86_400);
        let global = support::global(200).await;
        let (_wallet, _passport, public) = support::wallet_passport(&global).await;
        let mut config = support::community_config(directory.path(), "alpha", &public, 200);
        let mut rules = support::community_rules();
        crbk::RecordEpochSettings::define(&mut rules, &account.period_key).unwrap();
        crbk::OutcomeQuotaSettings::define(&mut rules, &account.settlement.quota_key).unwrap();
        rules
            .set_community(&account.period_key, Some(json!(86_400)))
            .unwrap();
        rules
            .set_community(&account.settlement.quota_key, Some(json!(4)))
            .unwrap();
        std::fs::write(&config.rulebook_file, serde_json::to_vec(&rules).unwrap()).unwrap();
        config.accounting = Some(account);
        Self {
            config,
            context_deadline,
            epoch: 4,
            _directory: directory,
            _global: global,
        }
    }
    pub async fn db(&self) -> crlt::Db {
        let db = crlt::Db::open(crlt::Config::new(&self.config.database_url, ""))
            .await
            .unwrap();
        db.migrate(&cvld::service::community_migrations())
            .await
            .unwrap();
        db
    }
    pub async fn native_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.db()
            .await
            .community("alpha")
            .unwrap()
            .query(
                "SELECT key,value FROM cvld_account_current ORDER BY key",
                (),
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| {
                let blob = |column| match row.get_value(column).unwrap() {
                    crlt::Value::Blob(bytes) => bytes.clone(),
                    _ => panic!("native owner value must be a blob"),
                };
                (blob(0), blob(1))
            })
            .collect()
    }
    pub async fn feed(&self, door: &Door) -> TrustFeed {
        let response = cvld::api::router(door.clone())
            .oneshot(
                Request::post("/v1/trust_feed")
                    .header("host", "api.alpha.example.test")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
    }
    pub fn check_feed(&self, feed: &TrustFeed) {
        let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
        assert_eq!(feed.policy_epoch, self.epoch);
        assert_eq!(
            ring.keys()[0].public_key(),
            ed25519_dalek::SigningKey::from_bytes(&[b'a'; 32])
                .verifying_key()
                .to_bytes()
        );
        let signed = ring
            .verify(
                feed.balance.as_ref().unwrap(),
                csgn::Kind::SettingsSnapshot,
                NOW,
            )
            .unwrap();
        let material: cblc::publication::PublicVerifierMaterial =
            serde_json::from_slice(signed.payload()).unwrap();
        material.validate_at("alpha", NOW).unwrap();
        assert_eq!(material.admission_policy_digest, [3; 32]);
        let capability = material.settlement.as_ref().unwrap();
        assert_eq!(
            (
                capability.policy_epoch,
                capability.period_seconds,
                capability.quota
            ),
            (self.epoch, 86_400, 4)
        );
        assert_eq!(capability.epoch.valid_until / 1000, self.context_deadline);
        assert!(
            material.record_epoch.is_none(),
            "empty bootstrap is not a G2 record decision"
        );
    }
    pub async fn seed_policy(&self, future: bool) {
        let mut config = self.duplicate_config();
        config.accounting = None;
        let door = Door::community(config, Arc::new(support::TestClock(AtomicU64::new(NOW))))
            .await
            .unwrap();
        assert_eq!(self.feed(&door).await.policy_epoch, self.epoch);
        door.shutdown_accounts().await.unwrap();
        drop(door);
        if future {
            let db = self.db().await;
            let scope = db.community("alpha").unwrap();
            let signer = csgn::PersistentSigner::open(
                csgn::LibsqlStore::new(scope),
                "alpha",
                csgn::SecretKey::from_seed(&mut [b'a'; 32]),
                cplc::day(NOW),
            )
            .await
            .unwrap();
            let mut policy = cplc::Policy::open(
                cmty::adapters::SharedRulebook::new(crbk::LibsqlStore::new(db.clone())),
                cplc::LibsqlStore::new(&db, "alpha").unwrap(),
                signer,
            )
            .await
            .unwrap();
            use crbk::Storage;
            let rules_store = crbk::LibsqlStore::new(db.clone());
            let latest = rules_store
                .load("alpha", crbk::Selection::Latest)
                .await
                .unwrap()
                .unwrap();
            // The current effective epoch is the original sum of the facade
            // and active Rulebook counters, not the caller's target alone.
            let book = serde_json::from_slice(&std::fs::read(&self.config.rulebook_file).unwrap())
                .unwrap();
            policy
                .schedule_rules(
                    Some(latest.revision),
                    crbk::Change {
                        rulebook: book,
                        announced_at: NOW as i64,
                        effective_at: (NOW + 1) as i64,
                        notice_seconds: 0,
                        policy_epoch: latest.change.policy_epoch + 1,
                    },
                )
                .await
                .unwrap();
            assert_eq!(policy.epoch(NOW).await.unwrap(), self.epoch);
            assert_eq!(policy.epoch(NOW + 1).await.unwrap(), self.epoch + 1);
        }
    }
}
