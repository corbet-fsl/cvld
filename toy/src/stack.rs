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
    host: &str,
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
            if lower.starts_with("host:") && !host.is_empty() {
                rewritten.push_str(&format!("Host: {host}\r\n"));
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
    let global_listen = process::port();
    fixtures::global(&global_dir, global_listen.clone(), 1000, now).await;
    // The community needs the global public documents at startup: read them from
    // the global service alone, stop it, then start both in one platform process.
    let public: cvld::api::GlobalPublic = {
        let probe = Service::start(
            &bin,
            &global_dir,
            "global",
            fixtures::WALLET.into(),
            &clock,
            Arc::new(Mutex::new(Metrics::default())),
        )?;
        serde_json::from_value(probe.initial.clone()).map_err(|_| "global public documents")?
    };
    let alpha_dir = dir.path().join("alpha");
    fs::create_dir(&alpha_dir).map_err(|_| "alpha directory")?;
    let alpha_listen = process::port();
    // The real accounting operator's activation probe is cut for the community "omega".
    let community_name = if std::env::var_os("CVLD_G5_ACCOUNT_CONFIG").is_some() {
        "omega"
    } else {
        "alpha"
    };
    fixtures::community(&alpha_dir, alpha_listen.clone(), community_name, &public, 1000);
    // Multi-tenant hosting (communities created at runtime behind the Host-routing front)
    // runs next to the real accounting operator; each created community derives its own.
    let hub = if std::env::var_os("CVLD_G5_ACCOUNT_CONFIG").is_some() {
        let hub_dir = dir.path().join("hub");
        fs::create_dir(&hub_dir).map_err(|_| "hub directory")?;
        // The template carries the platform-wide accounting (artifacts, limits, execution)
        // and names the directory where each created community's own inputs are derived.
        fixtures::community_with(&hub_dir, process::port(), "template", &public, 1000, true);
        let tenants = hub_dir.join("tenants");
        fs::create_dir(&tenants).map_err(|_| "tenants directory")?;
        let template_path = hub_dir.join("config.json");
        let mut template: serde_json::Value =
            serde_json::from_slice(&fs::read(&template_path).map_err(|_| "template")?)
                .map_err(|_| "template decodes")?;
        template["accounting"]["tenants_dir"] = tenants.to_string_lossy().as_ref().into();
        fs::write(
            &template_path,
            serde_json::to_vec(&template).map_err(|_| "encode template")?,
        )
        .map_err(|_| "write template")?;
        fs::write(hub_dir.join("master"), cpsd::rand::random::<[u8; 32]>())
            .map_err(|_| "hub master secret")?;
        let key = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-outform",
                "DER",
            ])
            .output()
            .map_err(|_| "openssl")?;
        if !key.status.success() {
            return Err("token issuer key generation".into());
        }
        fs::write(hub_dir.join("token-issuer.der"), key.stdout).map_err(|_| "token issuer key")?;
        Some(json!({
            "template_config": hub_dir.join("config.json"),
            "master_secret_file": hub_dir.join("master"),
            "token_issuer_file": hub_dir.join("token-issuer.der"),
            "shell_seconds": 7 * 86_400,
            "provisioner": {"kind": "noop"},
        }))
    } else {
        None
    };
    let mut platform = json!({
        "global_config": global_dir.join("config.json"),
        "community_configs": [alpha_dir.join("config.json")],
    });
    if let Some(hub) = hub {
        platform["hub"] = hub;
    }
    fs::write(
        global_dir.join("platform.json"),
        serde_json::to_vec(&platform).map_err(|_| "encode")?,
    )
    .map_err(|_| "write platform configuration")?;
    let global = Service::start(
        &bin,
        &global_dir,
        "platform",
        fixtures::WALLET.into(),
        &clock,
        Arc::new(Mutex::new(Metrics::default())),
    )?;
    let upstreams = [
        (global_listen.clone(), fixtures::WALLET),
        (alpha_listen, fixtures::ALPHA),
        (global_listen.clone(), fixtures::ROOT_ADMIN),
        // Created communities: the client's own Host header reaches the Host-routing front.
        (global_listen, ""),
    ];

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
        .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key)
        .map_err(|_| "tls configuration")?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    // One TLS front end per virtual host: the client insists that its https host
    // equals the host it sends, so each service gets its own loopback port.
    let mut ports = Vec::new();
    let mut proxies = Vec::new();
    for (upstream, host) in upstreams {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "tls listener")?;
        ports.push(listener.local_addr().map_err(|_| "tls address")?.port());
        let acceptor = acceptor.clone();
        proxies.push(tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let acceptor = acceptor.clone();
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(plain) = tokio::net::TcpStream::connect(&upstream).await else {
                        return;
                    };
                    relay(tls, plain, host).await;
                });
            }
        }));
    }
    let (port, alpha_port, root_port, passthrough_port) =
        (ports[0], ports[1], ports[2], ports[3]);
    eprintln!("stack listening on {port} {alpha_port} {root_port}");

    // Self-probe with the same client the devices use; reports only the outcome class.
    let probe = cvld::client::HttpClient::with_roots(
        format!("https://127.0.0.1:{port}"),
        "127.0.0.1".into(),
        None,
        &[cert_der.clone()],
    );
    match probe {
        Ok(client) => {
            let outcome = client.call("global_public", json!({})).await;
            eprintln!("stack probe: {:?}", outcome.map(|_| "ok"));
        }
        Err(error) => eprintln!("stack probe client: {error:?}"),
    }

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
    // The community device: wallet passport service first, then the community.
    let mut community = member.clone();
    community["community"] = json!(community_name);
    community["services"] = json!([
        {"scope": "global", "base": format!("https://127.0.0.1:{port}"), "host": "127.0.0.1"},
        {"scope": "community", "base": format!("https://127.0.0.1:{alpha_port}"), "host": "127.0.0.1"},
    ]);
    let community_path = out.join("alpha.json");
    fs::write(
        &community_path,
        serde_json::to_vec(&community).map_err(|_| "encode")?,
    )
    .map_err(|_| "write community configuration")?;
    // The platform Root device: admin host, vault page on the admin vault host.
    let root_origin = format!("https://{}", fixtures::ROOT_ORIGIN);
    let root = json!({
        "community": "global",
        "origin": root_origin,
        "role": "root",
        "primary": "global",
        "services": [{
            "scope": "global",
            "base": format!("https://127.0.0.1:{root_port}"),
            "host": "127.0.0.1",
        }],
        "login": {
            "page": "https://vault.root.example.test/login",
            "origin": "https://vault.root.example.test",
            "relying_party": "root.example.test",
        },
    });
    let root_path = out.join("root.json");
    fs::write(&root_path, serde_json::to_vec(&root).map_err(|_| "encode")?)
        .map_err(|_| "write root configuration")?;
    // With the real accounting operator, the production device composer needs its
    // settings: both services' pinned key rings, passkey contexts, and the prover.
    let device_settings = match std::env::var_os("CVLD_G5_ACCOUNT_CONFIG") {
        None => None,
        Some(account_path) => {
            let account: serde_json::Value =
                serde_json::from_slice(&fs::read(account_path).map_err(|_| "G5 configuration")?)
                    .map_err(|_| "G5 configuration decoding")?;
            let feed = |base: String, action: &'static str| {
                let roots = [cert_der.clone()];
                async move {
                    let client = cvld::client::HttpClient::with_roots(
                        base,
                        "127.0.0.1".into(),
                        None,
                        &roots,
                    )
                    .map_err(|_| "trust feed client")?;
                    let feed = client
                        .call(action, json!({}))
                        .await
                        .map_err(|_| "trust feed")?;
                    Ok::<_, &'static str>(feed["key_ring"].clone())
                }
            };
            let wallet_ring = feed(format!("https://127.0.0.1:{port}"), "wallet_trust_feed").await?;
            let community_ring =
                feed(format!("https://127.0.0.1:{alpha_port}"), "trust_feed").await?;
            let artifacts = &account["extension_artifacts"];
            let ca = out.join("ca.der");
            let settings = json!({
                "global": {
                    "origin": format!("https://127.0.0.1:{port}"),
                    "scope": "wallet",
                    "passkey_origin": format!("https://vault.{}", fixtures::WALLET),
                    "rp_id": fixtures::WALLET,
                    "trust_key_ring": wallet_ring,
                    "connect_host": "127.0.0.1",
                    "tls_root_files": [ca],
                },
                "community": {
                    "origin": format!("https://127.0.0.1:{alpha_port}"),
                    "scope": community_name,
                    "passkey_origin": format!("https://vault.{community_name}.{}", fixtures::DOMAIN),
                    "rp_id": format!("{community_name}.{}", fixtures::DOMAIN),
                    "trust_key_ring": community_ring,
                    "connect_host": "127.0.0.1",
                    "tls_root_files": [ca],
                },
                "community_name": community_name,
                "prover": {
                    "worker_executable": std::env::var("CMSG_NATIVE_PROVER_WORKER")
                        .map_err(|_| "set CMSG_NATIVE_PROVER_WORKER")?,
                    "circuit_file": artifacts["circuit_file"],
                    "keys_file": artifacts["keys_file"],
                    "srs_g1_file": artifacts["srs_g1_file"],
                    "srs_g2_file": artifacts["srs_g2_file"],
                },
            });
            let path = out.join("device.json");
            fs::write(&path, serde_json::to_vec(&settings).map_err(|_| "encode")?)
                .map_err(|_| "write device settings")?;
            Some(path)
        }
    };
    // The public synthetic enrolment capability of the test Root, never a production secret.
    println!(
        "{}",
        json!({
            "device_settings": device_settings,
            "passthrough_base": format!("https://127.0.0.1:{passthrough_port}"),
            "member_config": member_path,
            "community_config": community_path,
            "root_config": root_path,
            "root_bootstrap": global_dir.join("bootstrap"),
            "ca_der": out.join("ca.der"),
        })
    );
    // Hold the services until the owner closes our stdin.
    let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut tokio::io::sink()).await;
    for proxy in proxies {
        proxy.abort();
    }
    drop(global);
    Ok(())
}
