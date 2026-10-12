//! Real global service behind a TLS terminator, for external clients (the cmeet
//! end-to-end scenario). Usage: `cvld-stack OUT_DIR` with `CVLD_BIN` set.
//!
//! Writes `ca.der` (the only trust root) and `member.json` (public device
//! deployment data) into OUT_DIR, prints one JSON line, and stays up until stdin
//! closes. Nothing secret is written. The service runs at the wall clock, frozen
//! there by the faketime file the harness owns (a scenario lasts minutes).
#[path = "fixtures.rs"]
#[allow(dead_code)]
mod fixtures;
#[path = "process.rs"]
#[allow(dead_code)]
mod process;

use process::{Metrics, Result, Service};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

/// Forward HTTP/1.1 requests with a Content-Length body, replacing the Host
/// header by the service's real virtual host: the client insists that its https
/// host equals the host it sends, and a literal loopback address needs no DNS.
async fn relay(
    client: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    upstream: tokio::net::TcpStream,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut from_client, mut to_client) = tokio::io::split(client);
    let (mut from_upstream, mut to_upstream) = upstream.into_split();
    let back = tokio::spawn(async move {
        // Diagnostics: status line and error code only, never bodies of other kinds.
        let mut first = [0u8; 4096];
        while let Ok(read) = from_upstream.read(&mut first).await {
            if read == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&first[..read]);
            let status = text.lines().next().unwrap_or("");
            let error = text.split("\r\n\r\n").nth(1).unwrap_or("");
            eprintln!(
                "stack response: {status} {}",
                &error[..error.len().min(120)]
            );
            if to_client.write_all(&first[..read]).await.is_err() {
                break;
            }
        }
        let _ = to_client.shutdown().await;
    });
    let mut buffer: Vec<u8> = Vec::new();
    'requests: loop {
        let head_end = loop {
            if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break at + 4;
            }
            let mut chunk = [0u8; 8192];
            match from_client.read(&mut chunk).await {
                Ok(read) if read > 0 && buffer.len() < 65536 => {
                    buffer.extend_from_slice(&chunk[..read])
                }
                _ => break 'requests,
            }
        };
        let Ok(head) = std::str::from_utf8(&buffer[..head_end]) else {
            break;
        };
        eprintln!("stack request: {}", head.lines().next().unwrap_or(""));
        let mut rewritten = String::new();
        let mut length = 0usize;
        for line in head.split("\r\n").filter(|line| !line.is_empty()) {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("host:") {
                rewritten.push_str(&format!("Host: {}\r\n", fixtures::WALLET));
                continue;
            }
            if let Some(value) = lower.strip_prefix("content-length:") {
                length = value.trim().parse().unwrap_or(0);
            }
            rewritten.push_str(line);
            rewritten.push_str("\r\n");
        }
        rewritten.push_str("\r\n");
        if to_upstream.write_all(rewritten.as_bytes()).await.is_err() {
            break;
        }
        buffer.drain(..head_end);
        let mut remaining = length;
        while remaining > 0 {
            if buffer.is_empty() {
                let mut chunk = [0u8; 8192];
                match from_client.read(&mut chunk).await {
                    Ok(read) if read > 0 => buffer.extend_from_slice(&chunk[..read]),
                    _ => break 'requests,
                }
            }
            let take = remaining.min(buffer.len());
            if to_upstream.write_all(&buffer[..take]).await.is_err() {
                break 'requests;
            }
            buffer.drain(..take);
            remaining -= take;
        }
    }
    let _ = to_upstream.shutdown().await;
    let _ = back.await;
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("stack failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let out = PathBuf::from(std::env::args().nth(1).ok_or("usage: cvld-stack OUT_DIR")?);
    let bin = PathBuf::from(std::env::var("CVLD_BIN").map_err(|_| "set CVLD_BIN")?)
        .canonicalize()
        .map_err(|_| "CVLD_BIN is not a file")?;
    fs::create_dir_all(&out).map_err(|_| "output directory")?;
    let dir = tempfile::tempdir().map_err(|_| "temporary directory")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock")?
        .as_secs();
    let clock = dir.path().join("clock");
    process::clock(&clock, now);
    let global_dir = dir.path().join("global");
    fs::create_dir(&global_dir).map_err(|_| "global directory")?;
    fixtures::global(&global_dir, process::port(), 1000, now).await;
    let global = Service::start(
        &bin,
        &global_dir,
        "global",
        fixtures::WALLET.into(),
        &clock,
        Arc::new(Mutex::new(Metrics::default())),
    )?;
    let upstream = global.cli.base.trim_start_matches("http://").to_owned();

    // One self-signed end-entity certificate is the only trust root handed out.
    let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![
        "localhost".into(),
        fixtures::WALLET.into(),
        "127.0.0.1".into(),
    ])
    .map_err(|_| "certificate generation")?;
    let cert_der = cert.der().to_vec();
    fs::write(out.join("ca.der"), &cert_der).map_err(|_| "write trust root")?;
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    // Several rustls providers are linked; name the one this crate enables.
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "tls versions")?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der)], key)
        .map_err(|_| "tls configuration")?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "tls listener")?;
    let port = listener.local_addr().map_err(|_| "tls address")?.port();
    let proxy = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let upstream = upstream.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(tls) => tls,
                    Err(error) => {
                        eprintln!("stack tls accept failed: {error}");
                        return;
                    }
                };
                let Ok(plain) = tokio::net::TcpStream::connect(&upstream).await else {
                    return;
                };
                relay(tls, plain).await;
            });
        }
    });

    let origin = format!("https://{}", fixtures::WALLET);
    let member = json!({
        "community": "global",
        "origin": origin,
        "role": "member",
        "primary": "global",
        "services": [{
            "scope": "global",
            "base": format!("https://127.0.0.1:{port}"),
            "host": "127.0.0.1",
        }],
        "login": {
            "page": format!("https://vault.{}/login", fixtures::WALLET),
            "origin": format!("https://vault.{}", fixtures::WALLET),
            "relying_party": fixtures::WALLET,
        },
    });
    let member_path = out.join("member.json");
    fs::write(
        &member_path,
        serde_json::to_vec(&member).map_err(|_| "encode")?,
    )
    .map_err(|_| "write member configuration")?;
    println!(
        "{}",
        json!({
            "member_config": member_path,
            "ca_der": out.join("ca.der"),
        })
    );
    // Hold the services until the owner closes our stdin.
    let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut tokio::io::sink()).await;
    proxy.abort();
    drop(global);
    Ok(())
}
