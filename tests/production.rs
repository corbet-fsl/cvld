#![cfg(not(feature = "development-gate"))]

#[test]
fn production_binary_omits_the_development_action() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cvld"))
        .arg("openapi")
        .output()
        .unwrap();
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(document["paths"].get("/v1/development_gate").is_none());
    assert!(cvld::api::action("development_gate").is_none());
    assert!(
        cvld::mcp::tools()
            .iter()
            .all(|tool| tool.name != "development_gate")
    );
    assert!(
        cvld::cli::command()
            .try_get_matches_from(["cvld", "development_gate"])
            .is_err()
    );
}

#[test]
fn malformed_cli_input_is_not_repeated_in_diagnostics() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cvld"))
        .arg("synthetic-private-marker")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        cvld::error::Error::Invalid.to_string()
    );
}
