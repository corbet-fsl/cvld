use super::*;
use cmty::cplc::crbk;

const NOW: u64 = 1_800_000_000 + 12_345;
const FROM: u64 = 1_800_000_000 - 1_800_000_000 % 86_400;

fn rulebook() -> crbk::Rulebook {
    let mut rulebook = crbk::Rulebook::default();
    crbk::define_platform_settings(&mut rulebook).unwrap();
    rulebook
}

fn ledger(from: u64) -> serde_json::Value {
    serde_json::json!({
        "account": {
            "initialCredit": 20, "maximumAvailable": 100, "outgoingReservation": 5,
            "incomingReservation": 5, "policyRevision": 1, "policyValidFrom": from,
            "policyValidUntil": from + 10 * 365 * 86_400, "newcomerPeriod": 100,
            "rateWindow": 100, "newcomerAdmissions": 2, "maximumAdmissions": 10,
            "refillPeriod": 100, "refillUnits": 2, "abandonAfter": 200
        },
        "maxAuthorizationSeconds": 100,
        "maxProofBytes": 4194304,
        "checkpointPeriodSeconds": 86400
    })
}

fn template(dir: &Path) -> AccountConfig {
    fs::write(dir.join("ledger.json"), ledger(0).to_string()).unwrap();
    fs::write(
        dir.join("extension.json"),
        serde_json::json!({"revision": 1, "standingPolicyDigest": vec![7u8; 32]}).to_string(),
    )
    .unwrap();
    let artifacts = serde_json::json!({
        "manifest_file": "/m", "manifest_sha256": vec![1u8; 32], "circuit_file": "/c",
        "keys_file": "/k", "srs_g1_file": "/g1", "srs_g2_file": "/g2"
    });
    let execution = serde_json::json!({
        "executable": "/w", "timeout_ms": 1000, "maximum_parallel": 1,
        "max_proof_bytes": 1024, "threads": 1, "memory_megabytes": 64
    });
    serde_json::from_value(serde_json::json!({
        "period_key": "record/window",
        "ledger_policy_file": dir.join("ledger.json"),
        "extension_policy_file": dir.join("extension.json"),
        "admission_policy_digest": "AAAA",
        "operator_seed_file": "/unused",
        "certificate_seed_file": "/unused",
        "account_artifacts": artifacts,
        "extension_artifacts": artifacts,
        "activation_statement_file": "/unused",
        "activation_proof_file": "/unused",
        "account_execution": execution,
        "update_execution": execution,
        "anonymous_execution": execution,
        "extension_limits": {"global_burst": 1, "subject_burst": 1, "replenish_ms": 1, "maximum_keys": 1},
        "enrollment": {"max_members": 1, "max_retained_slots": 1, "max_publication_bytes": 1},
        "settlement": {
            "quota_key": "q", "epoch_file": "/unused", "private_key_file": "/unused",
            "room_epochs_file": "/unused", "incarnation": "x",
            "pending_capacity": 1, "issuance_members_capacity": 1
        },
        "max_request_bytes": 1024,
        "tenants_dir": dir.join("tenants"),
    }))
    .unwrap()
}

fn owner() -> [u8; 32] {
    czkp::activation_owner("alpha", &[9; 48])
}

fn statement(from: u64) -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": 2, "community": vec![1u8; 32], "owner": owner().to_vec(), "policyDigest": vec![3u8; 32],
        "enrollmentRoot": vec![4u8; 32], "now": NOW, "validUntil": NOW + 100, "genesis": true,
        "previousVersion": 0, "nextVersion": 0, "previousState": vec![0u8; 32], "nextState": vec![5u8; 32],
        "settlementMarker": vec![0u8; 32], "policy": ledger(from)["account"]
    })
}

fn activation(from: u64) -> Activation {
    Activation {
        statement: statement(from),
        proof: vec![1, 2, 3],
        owner: owner(),
    }
}

#[test]
fn terms_carry_todays_window_and_the_hubs_clock() {
    let dir = tempfile::tempdir().unwrap();
    let terms = template(dir.path()).terms(NOW, &rulebook()).unwrap();
    assert_eq!(terms.observed_at, NOW);
    assert_eq!(terms.ledger_policy["account"]["policyValidFrom"], FROM);
    assert_eq!(
        terms.ledger_policy["account"]["policyValidUntil"],
        FROM + 10 * 365 * 86_400
    );
    assert_eq!(terms.extension_policy["revision"], 1);
    // The standing digest is the rulebook's, not the file's (the file said 7).
    let digest: Vec<u8> = terms.extension_policy["standingPolicyDigest"]
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "13869f92e82373e15e5b9bbaf09bb0d2f4a71e7af912d20c68ae8ceb98710231"
    );
    // A device reads the same values the hub did.
    assert_eq!(terms.standing.len(), czkp::standing::RULEBOOK_KEYS.len());
    assert_eq!(terms.standing["voucher.slope.member"], 0.1);
    assert_eq!(terms.standing["standing.c0"], 3);
}

#[test]
fn an_activation_must_carry_exactly_todays_or_yesterdays_terms() {
    let dir = tempfile::tempdir().unwrap();
    let template = template(dir.path());
    assert_eq!(
        template
            .check_activation(&activation(FROM), NOW, &rulebook())
            .unwrap(),
        FROM
    );
    // A device that proved before midnight is still accepted.
    assert_eq!(
        template
            .check_activation(&activation(FROM - 86_400), NOW, &rulebook())
            .unwrap(),
        FROM - 86_400
    );
    for refused in [FROM - 2 * 86_400, FROM + 86_400, FROM + 5] {
        assert!(
            template
                .check_activation(&activation(refused), NOW, &rulebook())
                .is_err()
        );
    }
    // Another policy than the terms name.
    let mut other = activation(FROM);
    other.statement["policy"]["initialCredit"] = 21.into();
    assert!(template.check_activation(&other, NOW, &rulebook()).is_err());
    // No proof, or a proof beyond the bound.
    let mut empty = activation(FROM);
    empty.proof.clear();
    assert!(template.check_activation(&empty, NOW, &rulebook()).is_err());
    let mut huge = activation(FROM);
    huge.proof = vec![0; MAX_PROOF + 1];
    assert!(template.check_activation(&huge, NOW, &rulebook()).is_err());
}

#[test]
fn every_incarnation_has_its_own_keys_and_a_reopen_reuses_them() {
    let dir = tempfile::tempdir().unwrap();
    let template = template(dir.path());
    let rulebook = rulebook();
    let (first, second) = ([1u8; 32], [2u8; 32]);
    // A community cannot be opened without its stored activation.
    assert!(
        template
            .for_tenant("alpha", &first, NOW, &rulebook, None)
            .is_err()
    );
    let one = template
        .for_tenant(
            "alpha",
            &first,
            NOW,
            &rulebook,
            Some((&activation(FROM), FROM)),
        )
        .unwrap();
    let two = template
        .for_tenant(
            "alpha",
            &second,
            NOW,
            &rulebook,
            Some((&activation(FROM), FROM)),
        )
        .unwrap();
    let read = |path: &str| fs::read(path).unwrap();
    assert_ne!(read(&one.operator_seed_file), read(&two.operator_seed_file));
    // Default `certificate_key_scope` (platform): every created community keeps the
    // template's certificate issuer.
    assert_eq!(one.certificate_seed_file, template.certificate_seed_file);
    assert_eq!(two.certificate_seed_file, template.certificate_seed_file);
    // Community scope: each incarnation derives its own issuer, kept across a reopen.
    let mut own = template.clone();
    own.certificate_key_scope = crate::accounting::config::CertificateKeyScope::Community;
    let issuer = |seed: &[u8; 32], activation| {
        own.for_tenant("beta", seed, NOW, &rulebook, activation)
            .unwrap()
            .certificate_seed_file
    };
    let stored = activation(FROM);
    let (beta_one, beta_two) = (
        issuer(&first, Some((&stored, FROM))),
        issuer(&second, Some((&stored, FROM))),
    );
    assert_ne!(beta_one, template.certificate_seed_file);
    assert_ne!(read(&beta_one), read(&beta_two));
    assert_eq!(issuer(&first, None), beta_one);
    assert_ne!(
        read(&one.settlement.private_key_file),
        read(&two.settlement.private_key_file)
    );
    assert_ne!(one.settlement.incarnation, two.settlement.incarnation);
    assert_ne!(one.operator_seed_file, one.certificate_seed_file);
    assert!(one.tenants_dir.is_none());
    // Restart: nothing new is given, nothing changes, the key is not remade.
    let again = template
        .for_tenant("alpha", &first, NOW + 60, &rulebook, None)
        .unwrap();
    assert_eq!(
        read(&again.settlement.private_key_file),
        read(&one.settlement.private_key_file)
    );
    assert_eq!(
        read(&again.settlement.epoch_file),
        read(&one.settlement.epoch_file)
    );
    assert_eq!(
        read(&again.operator_seed_file),
        read(&one.operator_seed_file)
    );
    // The epoch names this community and the day; its key is RSA-3072 PKCS#1.
    let epoch: serde_json::Value =
        serde_json::from_slice(&read(&one.settlement.epoch_file)).unwrap();
    assert_eq!(epoch["community"], "alpha");
    assert_eq!(epoch["epoch"], NOW / 86_400);
    // A later day makes a new daily key beside the stored policy and activation.
    let next = template
        .for_tenant("alpha", &first, NOW + 86_400, &rulebook, None)
        .unwrap();
    assert_ne!(
        next.settlement.private_key_file,
        one.settlement.private_key_file
    );
    assert_eq!(next.ledger_policy_file, one.ledger_policy_file);
}

#[test]
fn forgetting_removes_one_incarnation_only() {
    let dir = tempfile::tempdir().unwrap();
    let template = template(dir.path());
    let rulebook = rulebook();
    let (first, second) = ([1u8; 32], [2u8; 32]);
    let one = template
        .for_tenant(
            "alpha",
            &first,
            NOW,
            &rulebook,
            Some((&activation(FROM), FROM)),
        )
        .unwrap();
    let two = template
        .for_tenant(
            "beta",
            &second,
            NOW,
            &rulebook,
            Some((&activation(FROM), FROM)),
        )
        .unwrap();
    template.forget_tenant(&first);
    template.forget_tenant(&first);
    assert!(!Path::new(&one.operator_seed_file).exists());
    assert!(Path::new(&two.operator_seed_file).exists());
}

#[test]
fn a_proof_made_for_another_creation_of_the_same_name_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let template = template(dir.path());
    let rulebook = rulebook();
    // The proof binds the first creation's token message.
    let proof = activation(FROM);
    assert!(template.check_activation(&proof, NOW, &rulebook).is_ok());
    // A later incarnation of "alpha" has another token message, hence another one-time
    // owner: the old proof does not carry it.
    let later = Activation {
        owner: czkp::activation_owner("alpha", &[10; 48]),
        ..proof.clone()
    };
    assert!(template.check_activation(&later, NOW, &rulebook).is_err());
    // Neither does a proof for the same message under another name.
    let other_name = Activation {
        owner: czkp::activation_owner("beta", &[9; 48]),
        ..proof.clone()
    };
    assert!(
        template
            .check_activation(&other_name, NOW, &rulebook)
            .is_err()
    );
    // The hub never trusts an unset one-time value.
    let unset = Activation {
        owner: [0; 32],
        statement: {
            let mut statement = proof.statement.clone();
            statement["owner"] = vec![0u8; 32].into();
            statement
        },
        ..proof
    };
    assert!(template.check_activation(&unset, NOW, &rulebook).is_err());
}
