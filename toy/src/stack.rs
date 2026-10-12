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
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), fixtures::WALLET.into()])
            .map_err(|_| "certificate generation")?;
    let cert_der = cert.der().to_vec();
    fs::write(out.join("ca.der"), &cert_der).map_err(|_| "write trust root")?;
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let config = ServerConfig::builder()
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
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut plain) = tokio::net::TcpStream::connect(&upstream).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
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
            "base": format!("https://localhost:{port}"),
            "host": fixtures::WALLET,
        }],
        "login": {
            "page": format!("{origin}/login"),
            "origin": origin,
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
        json!({"member_config": member_path, "ca_der": out.join("ca.der")})
    );
    // Hold the services until the owner closes our stdin.
    let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut tokio::io::sink()).await;
    proxy.abort();
    drop(global);
    Ok(())
}
