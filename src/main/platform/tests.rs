//! Every start refusal happens before any native owner or listener exists.
use super::*;
use serde_json::{Value, json};

fn global(listen: &str, domain: &str, shutdown: u64) -> Value {
    json!({
        "listen": listen, "domain": domain, "database_url": "file:///unused.db",
        "signing_seed_file": "unused", "issuer_key_file": "unused",
        "uniqueness_key_file": "unused", "policy_file": "unused",
        "policy_authority_file": "unused", "root_user": "unused",
        "shutdown_seconds": shutdown, "session_seconds": 600, "pending_capacity": 10,
        "throttle_burst": 10, "throttle_interval_ms": 1000, "publication_seconds": 172800,
        "signer_max_seconds": 86400, "development": false
    })
}
fn community(name: &str, listen: &str, domain: &str, shutdown: u64) -> Value {
    json!({
        "listen": listen, "domain": domain, "community": name,
        "database_url": "file:///unused.db", "signing_seed_file": "unused",
        "rulebook_file": "unused", "schema_file": "unused",
        "global_key_ring_file": "unused", "global_status_file": "unused",
        "minimum_global_epoch": 1, "minimum_global_revision": 1, "global_gates": [],
        "root": {"user": "unused"}, "admin": {"user": "unused"},
        "pending_days": 2, "lease_months": 1, "shutdown_seconds": shutdown,
        "session_seconds": 600, "pending_capacity": 10, "throttle_burst": 10,
        "throttle_interval_ms": 1000, "publication_seconds": 172800,
        "signer_max_seconds": 86400, "minimum_notice_seconds": 0,
        "voucher_provider": "sponsor", "voucher_public_key_file": "unused"
    })
}
fn write(dir: &std::path::Path, name: &str, value: &Value) -> String {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path.to_str().unwrap().to_owned()
}
/// Write the referenced configs and the platform file; return the latter's path.
fn platform(dir: &std::path::Path, global: Value, communities: &[Value], extra: Value) -> String {
    let mut files = json!({
        "global_config": write(dir, "global.json", &global),
        "community_configs": communities
            .iter()
            .enumerate()
            .map(|(index, value)| write(dir, &format!("community-{index}.json"), value))
            .collect::<Vec<_>>(),
    });
    if let (Some(files), Some(extra)) = (files.as_object_mut(), extra.as_object()) {
        files.extend(extra.clone());
    }
    write(dir, "platform.json", &files)
}
fn refused(path: &str) -> Option<Error> {
    read(path).err()
}

#[test]
fn a_valid_composition_uses_the_smallest_shutdown_budget() {
    let dir = tempfile::tempdir().unwrap();
    let path = platform(
        dir.path(),
        global("127.0.0.1:9000", "example.test", 30),
        &[
            community("alpha", "127.0.0.1:9001", "example.test", 20),
            community("beta", "127.0.0.1:9002", "example.test", 25),
        ],
        json!({}),
    );
    let prepared = read(&path).ok().unwrap();
    assert_eq!(prepared.communities.len(), 2);
    assert_eq!(prepared.budget, Duration::from_secs(20));
}

#[test]
fn unknown_fields_and_unreadable_or_invalid_files_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ok = [community("alpha", "127.0.0.1:9001", "example.test", 20)];
    let unknown = platform(
        dir.path(),
        global("127.0.0.1:9000", "example.test", 30),
        &ok,
        json!({"surprise": true}),
    );
    assert!(matches!(refused(&unknown), Some(Error::Invalid)));
    assert!(matches!(
        refused(dir.path().join("missing.json").to_str().unwrap()),
        Some(Error::Unavailable)
    ));
    let valid = platform(
        dir.path(),
        global("127.0.0.1:9000", "example.test", 30),
        &ok,
        json!({}),
    );
    std::fs::write(dir.path().join("community-0.json"), b"{").unwrap();
    assert!(matches!(refused(&valid), Some(Error::Invalid)));
    std::fs::remove_file(dir.path().join("community-0.json")).unwrap();
    assert!(matches!(refused(&valid), Some(Error::Unavailable)));
    std::fs::write(dir.path().join("global.json"), b"[]").unwrap();
    assert!(matches!(refused(&valid), Some(Error::Invalid)));
}

#[test]
fn domain_mismatch_duplicate_names_and_zero_budgets_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let global_ok = || global("127.0.0.1:9000", "example.test", 30);
    let mismatch = platform(
        dir.path(),
        global_ok(),
        &[community("alpha", "127.0.0.1:9001", "other.test", 20)],
        json!({}),
    );
    assert!(matches!(refused(&mismatch), Some(Error::Invalid)));
    let duplicate = platform(
        dir.path(),
        global_ok(),
        &[
            community("alpha", "127.0.0.1:9001", "example.test", 20),
            community("alpha", "127.0.0.1:9002", "example.test", 20),
        ],
        json!({}),
    );
    assert!(matches!(refused(&duplicate), Some(Error::Invalid)));
    let zero_community = platform(
        dir.path(),
        global_ok(),
        &[community("alpha", "127.0.0.1:9001", "example.test", 0)],
        json!({}),
    );
    assert!(matches!(refused(&zero_community), Some(Error::Invalid)));
    let zero_global = platform(
        dir.path(),
        global("127.0.0.1:9000", "example.test", 0),
        &[community("alpha", "127.0.0.1:9001", "example.test", 20)],
        json!({}),
    );
    assert!(matches!(refused(&zero_global), Some(Error::Invalid)));
}

#[test]
fn overlapping_binds_including_wildcards_and_bad_addresses_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    for (global_listen, community_listen) in [
        ("127.0.0.1:9000", "127.0.0.1:9000"),
        ("0.0.0.0:9000", "127.0.0.1:9000"),
        ("127.0.0.1:9000", "0.0.0.0:9000"),
        ("[::]:9000", "127.0.0.1:9000"),
        ("127.0.0.1:9000", "not-an-address"),
    ] {
        let path = platform(
            dir.path(),
            global(global_listen, "example.test", 30),
            &[community("alpha", community_listen, "example.test", 20)],
            json!({}),
        );
        assert!(
            matches!(refused(&path), Some(Error::Invalid)),
            "{global_listen} {community_listen}"
        );
    }
    let two_communities = platform(
        dir.path(),
        global("127.0.0.1:9000", "example.test", 30),
        &[
            community("alpha", "127.0.0.1:9001", "example.test", 20),
            community("beta", "127.0.0.1:9001", "example.test", 20),
        ],
        json!({}),
    );
    assert!(matches!(refused(&two_communities), Some(Error::Invalid)));
}
