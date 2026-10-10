#![cfg(all(feature = "development-gate", unix))]
mod support;
use cvld::{
    api::GlobalPublic,
    client::HttpClient,
    error::Error,
    service::{Clock, SystemClock},
};
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use support::*;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cvld"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn command_line_help_contract_and_private_failures_are_explicit() {
    for argument in ["--help", "--version", "openapi"] {
        let output = binary().arg(argument).output().await.unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        if argument == "openapi" {
            let document: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(document["paths"].get("/v1/development_gate").is_some());
        }
    }
    for args in [
        vec!["synthetic-private-marker"],
        vec!["global_public"],
        vec![
            "--host",
            WALLET,
            "global_public",
            "--request",
            "private-not-json",
        ],
        vec![
            "--host",
            WALLET,
            "--url",
            "invalid-private-url",
            "global_public",
        ],
    ] {
        let output = binary().args(args).output().await.unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            Error::Invalid.to_string()
        );
    }
    let dir = tempfile::tempdir().unwrap();
    for scope in ["global", "community"] {
        let output = binary()
            .args(["serve", scope, "--config"])
            .arg(dir.path().join("missing-private-config"))
            .output()
            .await
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            Error::Unavailable.to_string()
        );
    }
    let output = binary()
        .args(["--host", WALLET, "--session-file"])
        .arg(dir.path().join("missing-private-session"))
        .arg("global_public")
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        Error::Unavailable.to_string()
    );
}

fn address() -> String {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

async fn start(
    scope: &str,
    config: &Path,
    address: &str,
    host: &str,
    action: &str,
) -> (Child, Value) {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut child = binary()
            .args(["serve", scope, "--config"])
            .arg(config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let client = HttpClient::new(format!("http://{address}"), host.into(), None).unwrap();
        for _ in 0..500 {
            if let Ok(value) = client.call(action, json!({})).await {
                return (child, value);
            }
            if let Some(status) = child.try_wait().unwrap() {
                let output = child.wait_with_output().await.unwrap();
                panic!(
                    "startup failed: {status}; {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("local service did not start");
    })
    .await
    .expect("local startup exceeded its complete readiness deadline")
}

async fn stop(mut child: Child) {
    let pid = child.id().unwrap().to_string();
    assert!(
        Command::new("sh")
            .args(["-c", "kill -INT \"$1\"", "cvld-test", &pid])
            .status()
            .await
            .unwrap()
            .success()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_service_processes_start_publish_and_shutdown_cleanly() {
    let global_dir = tempfile::tempdir().unwrap();
    let mut global = global_config_at(global_dir.path(), 100, SystemClock.now()).await;
    global.listen = address();
    let global_path = global_dir.path().join("config.json");
    std::fs::write(&global_path, serde_json::to_vec(&global).unwrap()).unwrap();
    let (global_child, public) = start(
        "global",
        &global_path,
        &global.listen,
        WALLET,
        "global_public",
    )
    .await;
    let public: GlobalPublic = serde_json::from_value(public).unwrap();
    let community_dir = tempfile::tempdir().unwrap();
    let mut community = community_config(community_dir.path(), "startup", &public, 100);
    community.listen = address();
    let community_path = community_dir.path().join("config.json");
    std::fs::write(&community_path, serde_json::to_vec(&community).unwrap()).unwrap();
    let (community_child, feed) = start(
        "community",
        &community_path,
        &community.listen,
        "api.startup.example.test",
        "trust_feed",
    )
    .await;
    assert!(feed["manifest"].is_array());
    stop(community_child).await;
    stop(global_child).await;

    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_dir = tempfile::tempdir().unwrap();
    let mut global = global_config_at(occupied_dir.path(), 100, SystemClock.now()).await;
    let global_path = occupied_dir.path().join("config.json");
    global.listen = reserved.local_addr().unwrap().to_string();
    std::fs::write(&global_path, serde_json::to_vec(&global).unwrap()).unwrap();
    let output = binary()
        .args(["serve", "global", "--config"])
        .arg(&global_path)
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        Error::Unavailable.to_string()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_stdio_completes_the_official_handshake_and_clean_eof() {
    let service = global(100).await;
    let mut child = binary()
        .args(["--url", &service.base, "--host", WALLET, "mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
    for request in [
        json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{"protocolVersion":rmcp::model::ProtocolVersion::LATEST_WITH_INITIALIZE,"capabilities":{},"clientInfo":{"name":"cvld-test","version":"1"}}}),
        json!({"jsonrpc":"2.0", "id":2, "method":"tools/list"}),
        json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"global_public","arguments":{}}}),
        json!({"jsonrpc":"2.0", "id":4, "method":"tools/call", "params":{"name":"global_warn","arguments":{"user":"private"}}}),
    ] {
        input
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        let line = tokio::time::timeout(Duration::from_secs(10), output.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], request["id"]);
        assert!(response.get("error").is_none(), "{response}");
        if request["id"] == 1 {
            input
                .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
                .await
                .unwrap();
        } else if request["id"] == 2 {
            assert_eq!(
                response["result"]["tools"].as_array().unwrap().len(),
                cvld::api::ACTIONS.len()
            );
        } else if request["id"] == 4 {
            assert_eq!(response["result"]["isError"], true);
        }
    }
    drop(input);
    assert!(
        tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}
