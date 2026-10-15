use cmty::{cplc, cplc::crbk};
use cvld::{
    api::GlobalPublic,
    config::{CommunityConfig, Config, Operator},
};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::path::Path;

pub const NOW: u64 = 1_800_000_000;
pub const DOMAIN: &str = "toy.localhost";
pub const WALLET: &str = "wallet.toy.localhost";
pub const ROOT: &str = "api.root.toy.localhost";
pub const ALPHA: &str = "api.alpha.toy.localhost";
/// The Root operator host and its page origin host.
pub const ROOT_ADMIN: &str = "api.admin.root.toy.localhost";
pub const ROOT_ORIGIN: &str = "admin.root.toy.localhost";
fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_owned()
}
pub async fn global(dir: &Path, listen: String, burst: u32, now: u64) {
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
    let config = Config {
        listen,
        domain: DOMAIN.into(),
        contacts: None,
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
        pending_capacity: 1024,
        throttle_burst: burst,
        throttle_interval_ms: 60_000,
        publication_seconds: 172800,
        signer_max_seconds: 86_400 * 100,
        development: true,
        trusted_proxies: Vec::new(),
        ohttp: None,
        wallet: Some(wallet(dir)),
    };
    write(dir, "config.json", &serde_json::to_vec(&config).unwrap());
}
/// The explicit literal-wallet section: its own signing seed and publication file.
pub fn wallet(dir: &Path) -> cvld::config::WalletConfig {
    let mut rules = crbk::Rulebook::default();
    rules
        .define(
            "quota",
            crbk::Setting {
                value_type: crbk::SettingType::Integer,
                nullable: false,
                default: json!(17),
                bounds: crbk::Bounds {
                    min: Some(0.into()),
                    max: Some(100.into()),
                },
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
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
        cplc::SchemaVersions {
            purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
            current: 1,
            versions: vec![cplc::SchemaVersion {
                schema,
                changes: None,
            }],
        },
        std::collections::BTreeSet::new(),
        2 * 86_400,
    )
    .unwrap();
    cvld::config::WalletConfig {
        signing_seed_file: write(dir, "wallet-seed", &[47; 32]),
        publication_file: write(
            dir,
            "wallet-publication.json",
            &serde_json::to_vec(&publication).unwrap(),
        ),
        signer_max_seconds: 100 * 86_400,
        // Test secret: the wallet's confirmation-stamp key (one-day cohort).
        stamp_key_file: Some(write(dir, "wallet-stamp-key", &{
            use cpsd::rand::SeedableRng as _;
            let key = cpsd::StampIssuerKey::generate(
                &mut cpsd::rand::rngs::StdRng::from_seed([53; 32]),
                cpsd::KeyId::new("wallet-stamp-1").unwrap(),
                &cpsd::StampParams::new(86_400).unwrap(),
            )
            .unwrap();
            key.to_secret_bytes()
        })),
        stamp_limit: None,
        stamp_period_seconds: None,
    }
}
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
/// The real native accounting operator, when the toy job provides the assembled
/// G5 configuration (`tools/g5-account-config.py`, retained cblc artifacts).
/// Its Rulebook carries the period and the daily quota the operator reads.
pub fn accounting() -> Option<(cvld::accounting::AccountConfig, crbk::Rulebook)> {
    let path = std::env::var_os("CVLD_G5_ACCOUNT_CONFIG")?;
    let account: cvld::accounting::AccountConfig =
        serde_json::from_slice(&std::fs::read(path).expect("G5 account configuration"))
            .expect("G5 account configuration decodes");
    let mut rules = community_rules();
    crbk::RecordEpochSettings::define(&mut rules, &account.period_key).expect("period key");
    crbk::OutcomeQuotaSettings::define(&mut rules, &account.settlement.quota_key)
        .expect("quota key");
    rules
        .set_community(&account.period_key, Some(json!(86_400)))
        .expect("period");
    rules
        .set_community(&account.settlement.quota_key, Some(json!(4)))
        .expect("quota");
    Some((account, rules))
}

pub fn community(dir: &Path, listen: String, name: &str, public: &GlobalPublic, burst: u32) {
    community_with(dir, listen, name, public, burst, true);
}

/// A community configuration. `with_accounting` selects the real operator when the
/// assembled G5 configuration is provided (the hub template has none until the
/// operator state is derived per created community).
pub fn community_with(
    dir: &Path,
    listen: String,
    name: &str,
    public: &GlobalPublic,
    burst: u32,
    with_accounting: bool,
) {
    let (accounting, rules) = match accounting().filter(|_| with_accounting) {
        Some((account, rules)) => (Some(account), rules),
        None => (None, community_rules()),
    };
    let config = CommunityConfig {
        stamp_cohort_seconds: None,
        founding_seed: None,
        listen,
        domain: DOMAIN.into(),
        community: name.into(),
        payments: None,
        database_url: format!("file://{}", dir.join("community.db").display()),
        database_token_file: None,
        signing_seed_file: write(dir, "signer", &cpsd::rand::random::<[u8; 32]>()),
        rulebook_file: write(
            dir,
            "rulebook",
            &serde_json::to_vec(&rules).unwrap(),
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
        pending_capacity: 1024,
        throttle_burst: burst,
        throttle_interval_ms: 60_000,
        publication_seconds: 2 * 86_400,
        signer_max_seconds: 10 * 366 * 86_400,
        minimum_notice_seconds: 0,
        voucher_provider: "sponsor".into(),
        accounting,
        trusted_proxies: Vec::new(),
        creation: None,
        shared_database: false,
        ohttp: None,
    };
    write(dir, "config.json", &serde_json::to_vec(&config).unwrap());
}
