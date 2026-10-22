#![cfg(feature = "server")]

use cvld::config::{CommunityConfig, RootCommunityConfig};
use serde_json::{Value, json};

fn community() -> Value {
    json!({
        "listen": "127.0.0.1:18443",
        "domain": "example.test",
        "community": "root",
        "database_url": "file:///tmp/cvld-config-test.db",
        "database_token_file": null,
        "signing_seed_file": "fixture/community-signer",
        "rulebook_file": "fixture/rulebook.json",
        "schema_file": "fixture/schema.json",
        "global_key_ring_file": "fixture/global-ring",
        "global_status_file": "fixture/global-status",
        "minimum_global_epoch": 1,
        "minimum_global_revision": 1,
        "global_gates": ["development"],
        "root": {"user": "00000000-0000-4000-8000-000000000001", "bootstrap_file": null},
        "admin": {"user": "00000000-0000-4000-8000-000000000002", "bootstrap_file": null},
        "pending_days": 2,
        "lease_months": 1,
        "shutdown_seconds": 10,
        "session_seconds": 600,
        "pending_capacity": 100,
        "throttle_burst": 100,
        "throttle_interval_ms": 60000,
        "trusted_proxies": [],
        "publication_seconds": 172800,
        "signer_max_seconds": 8640000,
        "minimum_notice_seconds": 0,
        "voucher_provider": "sponsor",
        "payments": null,
        "accounting": null,
        "creation": null,
        "shared_database": false
    })
}

fn root() -> Value {
    json!({"community": community(), "root_board_public_key_file": "fixture/root-public"})
}

#[test]
fn explicit_root_configuration_round_trips_without_issuer_secret() {
    let value = root();
    let config: RootCommunityConfig = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(config.listen(), "127.0.0.1:18443");
    assert_eq!(serde_json::to_value(config).unwrap(), value);
    // Reading configuration must not try to read its referenced public descriptor.
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("root.json");
    std::fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(RootCommunityConfig::read(file.to_str().unwrap()).is_ok());
    assert!(serde_json::from_value::<CommunityConfig>(value).is_err());
    assert!(serde_json::from_value::<RootCommunityConfig>(community()).is_err());
}

#[test]
fn unknown_fields_and_secret_configuration_are_refused_at_each_boundary() {
    for field in [
        "root_board_issuer_key_file",
        "issuer_key_file",
        "system_root",
        "extra",
    ] {
        let mut value = root();
        value[field] = json!("unaccepted");
        assert!(
            serde_json::from_value::<RootCommunityConfig>(value).is_err(),
            "{field}"
        );
    }
    for field in [
        "issuer_key_file",
        "root_board_public_key_file",
        "system_root",
        "extra",
    ] {
        let mut value = root();
        value["community"][field] = json!("unaccepted");
        assert!(
            serde_json::from_value::<RootCommunityConfig>(value).is_err(),
            "{field}"
        );
    }
    for operator in ["root", "admin"] {
        let mut value = root();
        value["community"][operator]["role"] = json!("root");
        assert!(serde_json::from_value::<RootCommunityConfig>(value).is_err());
    }
}

#[test]
fn required_configuration_and_operator_fields_cannot_be_omitted() {
    for field in ["community", "root_board_public_key_file"] {
        let mut value = root();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<RootCommunityConfig>(value).is_err(),
            "{field}"
        );
    }
    for field in community().as_object().unwrap().keys() {
        if [
            "database_token_file",
            "payments",
            "accounting",
            "trusted_proxies",
            "creation",
            "shared_database",
        ]
        .contains(&field.as_str())
        {
            continue;
        }
        let mut value = community();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<CommunityConfig>(value).is_err(),
            "{field}"
        );
    }
    for operator in ["root", "admin"] {
        let mut value = community();
        value[operator].as_object_mut().unwrap().remove("user");
        assert!(serde_json::from_value::<CommunityConfig>(value).is_err());
    }
}

#[test]
fn optional_credentials_remain_optional() {
    let mut value = community();
    value.as_object_mut().unwrap().remove("database_token_file");
    for operator in ["root", "admin"] {
        value[operator]
            .as_object_mut()
            .unwrap()
            .remove("bootstrap_file");
    }
    let config: CommunityConfig = serde_json::from_value(value).unwrap();
    assert!(config.database_token_file.is_none());
    assert!(config.root.bootstrap_file.is_none());
    assert!(config.admin.bootstrap_file.is_none());
}

#[test]
fn trusted_constructor_and_file_reader_require_root_scope_and_public_path() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("root.json");
    // The public descriptor path is required whatever the community is called (17.6: the board is
    // decided by its descriptor, not by the name "root").
    for name in ["alpha", "root"] {
        let mut value = community();
        value["community"] = json!(name);
        let config: CommunityConfig = serde_json::from_value(value.clone()).unwrap();
        assert!(RootCommunityConfig::new(config, String::new()).is_err());
        let value = json!({"community": value, "root_board_public_key_file": ""});
        std::fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(RootCommunityConfig::read(file.to_str().unwrap()).is_err());
    }
    // A board community may carry any name; only the descriptor path decides.
    let mut value = community();
    value["community"] = json!("alpha");
    let config: CommunityConfig = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        RootCommunityConfig::new(config, "fixture/root-public".into())
            .unwrap()
            .community_name(),
        "alpha"
    );
}

#[test]
fn root_board_serve_mode_requires_explicit_configuration_and_stays_distinct() {
    for mode in ["root-board", "community"] {
        let matches = cvld::cli::command()
            .try_get_matches_from(["cvld", "serve", mode, "--config", "fixture/config.json"])
            .unwrap();
        let (command, serve) = matches.subcommand().unwrap();
        assert_eq!(command, "serve");
        let (selected, args) = serve.subcommand().unwrap();
        assert_eq!(selected, mode);
        assert_eq!(
            args.get_one::<String>("config").unwrap(),
            "fixture/config.json"
        );
        assert!(
            cvld::cli::command()
                .try_get_matches_from(["cvld", "serve", mode])
                .is_err()
        );
    }
    assert!(
        cvld::cli::command()
            .try_get_matches_from([
                "cvld",
                "serve",
                "community",
                "--root-board",
                "--config",
                "fixture/config.json"
            ])
            .is_err()
    );
}
