#![cfg(feature = "development-gate")]
//! The real binary: command-line failures, configuration loading, serving and shutdown.
mod support;
use cvld::{
    api::{self, GlobalPublic},
    client::HttpClient,
    error::Error,
};
use serde_json::json;
use std::{process::Stdio, time::Duration};
use support::*;
use tokio::process::{Child, Command};

fn cvld() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cvld"));
    command.stdin(Stdio::null()).kill_on_drop(true);
    command
}

async fn run(args: &[&str]) -> std::process::Output {
    cvld().args(args).output().await.unwrap()
}

/// Run a command that must fail, print nothing on stdout and return stderr.
async fn refused(args: &[&str]) -> String {
    let output = run(args).await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    String::from_utf8(output.stderr).unwrap().trim().to_owned()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn serve_binary(scope: &str, config: &str) -> Child {
    cvld()
        .args(["serve", scope, "--config", config])
        .spawn()
        .unwrap()
}

async fn ready(child: &mut Child, port: u16) {
    for _ in 0..200 {
        assert!(
            child.try_wait().unwrap().is_none(),
            "the service exited before it listened"
        );
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the service never listened");
}

/// Interrupt the service the way an operator does and require a clean exit.
async fn interrupt(mut child: Child) {
    // Let the maintenance task run once and the shutdown handler arm.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let pid = child.id().unwrap();
    let status = Command::new("bash")
        .arg("-c")
        .arg(format!("kill -INT {pid}"))
        .status()
        .await
        .unwrap();
    assert!(status.success());
    let exit = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(exit.success());
}

#[tokio::test]
async fn help_and_version_print_and_succeed() {
    let help = run(&["--help"]).await;
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout).unwrap().contains("serve"));
    let version = run(&["--version"]).await;
    assert!(version.status.success());
    assert!(
        String::from_utf8(version.stdout)
            .unwrap()
            .contains(env!("CARGO_PKG_VERSION"))
    );
}

#[tokio::test]
async fn malformed_command_lines_fail_with_one_redacted_category() {
    let invalid = Error::Invalid.to_string();
    for args in [
        vec![],
        vec!["--synthetic-private-marker"],
        vec!["serve"],
        vec!["serve", "global"],
        vec!["serve", "unknown", "--config", "synthetic-private-marker"],
        vec!["lobby", "--request"],
    ] {
        assert_eq!(refused(&args).await, invalid);
    }
}

#[tokio::test]
async fn the_openapi_subcommand_prints_the_registered_contract() {
    let output = run(&["openapi"]).await;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{}\n", api::openapi_json())
    );
}

#[tokio::test]
async fn unreadable_or_invalid_inputs_fail_closed_before_any_service_starts() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing").to_str().unwrap().to_owned();
    let broken = write(dir.path(), "broken.json", b"{");
    let invalid = Error::Invalid.to_string();
    let unavailable = Error::Unavailable.to_string();
    for scope in ["global", "community"] {
        assert_eq!(
            refused(&["serve", scope, "--config", &missing]).await,
            unavailable
        );
        assert_eq!(
            refused(&["serve", scope, "--config", &broken]).await,
            invalid
        );
    }
    let local = "http://127.0.0.1:1";
    assert_eq!(
        refused(&[
            "--url",
            local,
            "--host",
            "h",
            "--session-file",
            &missing,
            "global_public"
        ])
        .await,
        unavailable
    );
    assert_eq!(
        refused(&[
            "--url",
            "ftp://example.test",
            "--host",
            "h",
            "global_public"
        ])
        .await,
        invalid
    );
    assert_eq!(refused(&["--url", local, "global_public"]).await, invalid);
    assert_eq!(
        refused(&[
            "--url",
            local,
            "--host",
            "h",
            "global_public",
            "--request",
            "{"
        ])
        .await,
        invalid
    );
    // A closed port is an unknown outcome, never a retry.
    assert_eq!(
        refused(&["--url", local, "--host", "h", "global_public"]).await,
        Error::Reconcile.to_string()
    );
    // MCP needs a peer on stdin; none is a failed start, not a hang.
    assert_eq!(
        refused(&["--url", local, "--host", "h", "mcp"]).await,
        unavailable
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_the_global_door_until_interrupted() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = global_config(dir.path(), 100, real_now()).await;
    let port = free_port();
    config.listen = format!("127.0.0.1:{port}");
    let path = write(
        dir.path(),
        "serve.json",
        &serde_json::to_vec(&config).unwrap(),
    );
    let mut child = serve_binary("global", &path);
    ready(&mut child, port).await;
    let client = HttpClient::new(format!("http://127.0.0.1:{port}"), WALLET.into(), None).unwrap();
    let public = client.call("global_public", json!({})).await.unwrap();
    assert!(public["issuer"].is_array());
    interrupt(child).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_a_community_door_until_interrupted() {
    let now = real_now();
    let global = global_at(100, now).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut config = community_config(dir.path(), "served", &public, 100);
    let port = free_port();
    config.listen = format!("127.0.0.1:{port}");
    let path = write(
        dir.path(),
        "serve.json",
        &serde_json::to_vec(&config).unwrap(),
    );
    let mut child = serve_binary("community", &path);
    ready(&mut child, port).await;
    let client = HttpClient::new(
        format!("http://127.0.0.1:{port}"),
        "api.served.example.test".into(),
        None,
    )
    .unwrap();
    let feed = client.call("trust_feed", json!({})).await.unwrap();
    assert!(feed["manifest"].is_array());
    interrupt(child).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_port_that_is_already_bound_stops_the_binary_as_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = global_config(dir.path(), 100, real_now()).await;
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    config.listen = format!("127.0.0.1:{}", held.local_addr().unwrap().port());
    let path = write(
        dir.path(),
        "serve.json",
        &serde_json::to_vec(&config).unwrap(),
    );
    assert_eq!(
        refused(&["serve", "global", "--config", &path]).await,
        Error::Unavailable.to_string()
    );
    drop(held);
}
