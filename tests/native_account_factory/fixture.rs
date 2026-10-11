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
fn required_file(variable: &str, maximum: usize) -> Vec<u8> {
    let path = PathBuf::from(std::env::var_os(variable).expect(variable));
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
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
impl Fixture {
    pub async fn new() -> Self {
        // This is operator fixture configuration of the ACTUAL application
        // types and pins. It is not part of a public member/provider DTO.
        let mut account: AccountConfig =
            serde_json::from_slice(&required_file("CVLD_G5_ACCOUNT_CONFIG", 1024 * 1024))
                .expect("explicit native artifact/worker/key configuration required");
        let probe_bytes = required_file("CVLD_ALPHA_ACTIVATION_PROBE", 4 * 1024 * 1024);
        // The expected retained-byte pin is supplied independently of the
        // downloaded probe. Actual native verification remains mandatory.
        let expected = std::env::var("CVLD_ALPHA_ACTIVATION_SHA256").unwrap();
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
        let context_deadline = epoch["validUntil"].as_u64().unwrap() / 1000;
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
        let mut config = self.config.clone();
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
                crbk::Rules::new(crbk::LibsqlStore::new(db.clone())),
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
