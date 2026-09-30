use cmnt::{cplc, cplc::crbk};
use cvld::{
    api::GlobalPublic,
    config::{CommunityConfig, Config, Operator},
};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::path::Path;

pub const NOW: u64 = 1_800_000_000;
pub const DOMAIN: &str = "example.test";
pub const WALLET: &str = "wallet.example.test";
pub const ROOT: &str = "api.root.example.test";
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
    let policy = cglb::Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: (now / 86_400 + 40) * 86_400,
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
        session_seconds: 600,
        pending_capacity: 1024,
        throttle_burst: burst,
        throttle_interval_ms: 60_000,
        publication_seconds: 172800,
        signer_max_seconds: 86_400 * 100,
        development: true,
    };
    write(dir, "config.json", &serde_json::to_vec(&config).unwrap());
}
pub fn community_rules() -> crbk::Rulebook {
    let mut rules = crbk::Rulebook::default();
    crbk::define_membership_settings(&mut rules).unwrap();
    for (level, gate, provider) in [
        (
            crbk::GateLevel::Global,
            "development",
            cmnt::PASSPORT_PROVIDER,
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
            crbk::action_key(cmnt::ADMISSION_ACTION),
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
pub fn community(dir: &Path, listen: String, name: &str, public: &GlobalPublic, burst: u32) {
    let config = CommunityConfig {
        listen,
        domain: DOMAIN.into(),
        community: name.into(),
        database_url: format!("file://{}", dir.join("community.db").display()),
        database_token_file: None,
        signing_seed_file: write(dir, "signer", &cpsd::rand::random::<[u8; 32]>()),
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
        session_seconds: 600,
        pending_capacity: 1024,
        throttle_burst: burst,
        throttle_interval_ms: 60_000,
        publication_seconds: 2 * 86_400,
        signer_max_seconds: 10 * 366 * 86_400,
        minimum_notice_seconds: 0,
        voucher_provider: "sponsor".into(),
        voucher_public_key_file: write(
            dir,
            "voucher-key",
            SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes(),
        ),
    };
    write(dir, "config.json", &serde_json::to_vec(&config).unwrap());
}
