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
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        crypto::CryptoProvider,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
    },
};

/// The toy's one trust root. Its parameters are fixed, so a continued state rebuilds
/// the same issuer from the saved key alone.
fn root_params() -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cvld toy root");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
}

/// Serves every toy host: a leaf for the name the client dials, minted once and signed
/// by the root. A created community is dialed by names (`api.<address>.toy.localhost`)
/// that no certificate made at start can list.
struct Leaves {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    provider: Arc<CryptoProvider>,
    minted: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for Leaves {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Leaves")
    }
}

impl Leaves {
    fn mint(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).ok()?;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let key = rcgen::KeyPair::generate().ok()?;
        let cert = params.signed_by(&key, &self.issuer).ok()?;
        let signing = self
            .provider
            .key_provider
            .load_private_key(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            )))
            .ok()?;
        Some(Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing)))
    }
}

impl ResolvesServerCert for Leaves {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // No SNI: the client dialed a literal loopback address.
        let name = hello
            .server_name()
            .unwrap_or("127.0.0.1")
            .to_ascii_lowercase();
        let toy = name
            .strip_suffix(fixtures::DOMAIN)
            .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'));
        if !(toy || name == "localhost" || name == "127.0.0.1") {
            return None;
        }
        let mut minted = self.minted.lock().ok()?;
        if let Some(leaf) = minted.get(&name) {
            return Some(leaf.clone());
        }
        let leaf = self.mint(&name)?;
        minted.insert(name, leaf.clone());
        Some(leaf)
    }
}

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
            if lower.starts_with("host:") && host.is_empty() {
                // Pass-through: keep the client's own host, without the port.
                let name = line[5..].trim();
                let name = name.rsplit_once(':').map_or(name, |(head, _)| head);
                rewritten.push_str(&format!("Host: {name}\r\n"));
                continue;
            }
            if lower.starts_with("host:") {
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(text: &str) -> Result<Vec<u8>> {
    (0..text.len() / 2)
        .map(|i| {
            u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| "saved certificate".into())
        })
        .collect()
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
    // Saved test states: with CVLD_STACK_STATE the stack keeps its databases, keys, ports and
    // certificate in that directory (nothing is removed on exit), and a stack started on a
    // directory that already holds a state continues it. Without it the stack is throwaway.
    let state_root = std::env::var_os("CVLD_STACK_STATE").map(PathBuf::from);
    let temp = match &state_root {
        Some(root) => {
            fs::create_dir_all(root).map_err(|_| "state directory")?;
            None
        }
        None => Some(tempfile::tempdir().map_err(|_| "temporary directory")?),
    };
    let base_dir: PathBuf = state_root.clone().unwrap_or_else(|| {
        temp.as_ref()
            .map(|t| t.path().to_owned())
            .unwrap_or_default()
    });
    let saved_path = base_dir.join("stack-saved.json");
    let saved: Option<serde_json::Value> = if state_root.is_some() {
        fs::read(&saved_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    } else {
        None
    };
    struct Dir(PathBuf);
    impl Dir {
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    let dir = Dir(base_dir);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock")?
        .as_secs();
    let clock = dir.path().join("clock");
    process::clock(&clock, now);
    // The services read this file as their clock. A long-running stack keeps real time
    // moving (a frozen server clock makes every ceremony look expired to a later client).
    let ticking = clock.clone();
    let clock_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Ok(elapsed) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            {
                process::clock(&ticking, elapsed.as_secs());
            }
        }
    });
    let global_dir = dir.path().join("global");
    let alpha_dir = dir.path().join("alpha");
    let resume = saved.is_some();
    let saved_text = |key: &str| {
        saved
            .as_ref()
            .and_then(|value| value[key].as_str())
            .map(str::to_owned)
    };
    let global_listen = saved_text("global_listen").unwrap_or_else(process::port);
    let alpha_listen = saved_text("alpha_listen").unwrap_or_else(process::port);
    // The real accounting operator's activation probe is cut for the community "omega".
    let community_name = if std::env::var_os("CVLD_G5_ACCOUNT_CONFIG").is_some() {
        "omega"
    } else {
        "alpha"
    };
    // A continued state keeps its directories, configurations and platform composition as saved.
    if !resume {
        fs::create_dir(&global_dir).map_err(|_| "global directory")?;
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
        fs::create_dir(&alpha_dir).map_err(|_| "alpha directory")?;
        fixtures::community(
            &alpha_dir,
            alpha_listen.clone(),
            community_name,
            &public,
            1000,
        );
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
            // Created communities prove their own activation, so they take the G5 fixture's
            // template terms (rate window = checkpoint period) and a grant that covers them.
            let ledger = std::path::Path::new(
                template["accounting"]["ledger_policy_file"]
                    .as_str()
                    .ok_or("template ledger policy")?,
            )
            .with_file_name("template-ledger-policy.json");
            let ledger = ledger.to_str().ok_or("template ledger path")?.to_owned();
            template["session_seconds"] = fixtures::grant_seconds(&ledger).into();
            template["accounting"]["ledger_policy_file"] = ledger.into();
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
            fs::write(hub_dir.join("token-issuer.der"), key.stdout)
                .map_err(|_| "token issuer key")?;
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
    }
    let global = Service::start(
        &bin,
        &global_dir,
        "platform",
        fixtures::WALLET.into(),
        &clock,
        Arc::new(Mutex::new(Metrics::default())),
    )?;
    let alpha_host: &'static str =
        Box::leak(format!("api.{community_name}.{}", fixtures::DOMAIN).into_boxed_str());
    let (upstream_global, upstream_alpha) = (global_listen.clone(), alpha_listen.clone());
    // The Forum of created communities (cfrm's own multi-tenant `serve`), when the harness
    // names its binary and the hub runs: one process for every community the hub creates.
    let forum_bin = std::env::var_os("CFRM_BIN")
        .filter(|_| std::env::var_os("CVLD_G5_ACCOUNT_CONFIG").is_some())
        .map(PathBuf::from);
    let forum_listen = forum_bin
        .as_ref()
        .map(|_| saved_text("forum_listen").unwrap_or_else(process::port));
    let upstreams = [
        (global_listen.clone(), fixtures::WALLET),
        (alpha_listen.clone(), alpha_host),
        (global_listen.clone(), fixtures::ROOT_ADMIN),
        // Created communities: the client's own Host header reaches the Host-routing front.
        (global_listen.clone(), ""),
    ];

    // One root certificate is the only trust root handed out; every host's leaf is minted
    // from it on first use. A continued state keeps the root (the devices pin it) and the
    // four front-end ports.
    let (cert_der, key_der) = match (saved_text("cert_der"), saved_text("key_der")) {
        (Some(cert), Some(key)) => (hex_decode(&cert)?, hex_decode(&key)?),
        _ => {
            let key = rcgen::KeyPair::generate().map_err(|_| "root key generation")?;
            let cert = root_params()
                .self_signed(&key)
                .map_err(|_| "root certificate generation")?;
            (cert.der().to_vec(), key.serialize_der())
        }
    };
    fs::write(out.join("ca.der"), &cert_der).map_err(|_| "write trust root")?;
    let root_key = rcgen::KeyPair::try_from(key_der.as_slice()).map_err(|_| "root key")?;
    // Several rustls providers are linked; name the one this crate enables.
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let leaves = Leaves {
        issuer: rcgen::Issuer::new(root_params(), root_key),
        provider: provider.clone(),
        minted: Mutex::new(HashMap::new()),
    };
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "tls versions")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(leaves));
    let acceptor = TlsAcceptor::from(Arc::new(config));
    // One TLS front end per virtual host: the client insists that its https host
    // equals the host it sends, so each service gets its own loopback port.
    let saved_ports: Vec<u16> = saved
        .as_ref()
        .and_then(|value| value["ports"].as_array())
        .map(|ports| {
            ports
                .iter()
                .filter_map(|p| p.as_u64().map(|p| p as u16))
                .collect()
        })
        .unwrap_or_default();
    let mut ports = Vec::new();
    let mut proxies = Vec::new();
    for (index, (upstream, host)) in upstreams.into_iter().enumerate() {
        let wanted = saved_ports.get(index).copied().unwrap_or(0);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", wanted))
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
    // Created communities at their production names on the default HTTPS port, as a deployment
    // serves them: `<address>.<base>` is the community's Forum (and the origin its members present
    // there), `api.<address>.<base>` its door, from which the Forum also follows the community's
    // feed. The harness runs the stack in its own network namespace as root, so the port is
    // free; elsewhere no created community has a Forum.
    let mut forum = None;
    if let (Some(bin), Some(listen)) = (&forum_bin, &forum_listen) {
        let mut bound = false;
        for address in ["127.0.0.1:443", "[::1]:443"] {
            match tokio::net::TcpListener::bind(address).await {
                Ok(listener) => {
                    bound = true;
                    let (acceptor, hub, forum) =
                        (acceptor.clone(), upstream_global.clone(), listen.clone());
                    proxies.push(tokio::spawn(async move {
                        loop {
                            let Ok((tcp, _)) = listener.accept().await else {
                                continue;
                            };
                            let (acceptor, hub, forum) =
                                (acceptor.clone(), hub.clone(), forum.clone());
                            tokio::spawn(async move {
                                let Ok(tls) = acceptor.accept(tcp).await else {
                                    return;
                                };
                                let community = tls
                                    .get_ref()
                                    .1
                                    .server_name()
                                    .and_then(|name| name.strip_suffix(fixtures::DOMAIN))
                                    .and_then(|label| label.strip_suffix('.'))
                                    .is_some_and(|label| {
                                        !label.is_empty() && !label.contains('.') && label != "wallet"
                                    });
                                let upstream = if community { forum } else { hub };
                                let Ok(plain) = tokio::net::TcpStream::connect(&upstream).await
                                else {
                                    return;
                                };
                                relay(tls, plain, "").await;
                            });
                        }
                    }));
                }
                Err(_) => eprintln!("stack: no listener on {address}"),
            }
        }
        if !bound {
            return Err("created communities need port 443 (run the stack in its own network namespace)".into());
        }
        forum = Some(start_forum(
            bin,
            &dir.path().join("forum"),
            listen,
            &upstream_global,
            &cert_der,
        )?);
    }
    if state_root.is_some() && !resume {
        // Test state (public values and the test certificate key); written once the stack is up.
        let record = json!({
            "global_listen": upstream_global,
            "alpha_listen": upstream_alpha,
            "forum_listen": forum_listen,
            "ports": ports,
            "cert_der": hex_encode(&cert_der),
            "key_der": hex_encode(&key_der),
        });
        fs::write(
            &saved_path,
            serde_json::to_vec(&record).map_err(|_| "encode")?,
        )
        .map_err(|_| "write stack state")?;
    }
    let (port, alpha_port, root_port, passthrough_port) = (ports[0], ports[1], ports[2], ports[3]);
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
            "page": "https://vault.root.toy.localhost/login",
            "origin": "https://vault.root.toy.localhost",
            "relying_party": "root.toy.localhost",
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
                    Ok::<_, &'static str>(feed)
                }
            };
            let wallet_ring = feed(format!("https://127.0.0.1:{port}"), "wallet_trust_feed")
                .await?["key_ring"]
                .clone();
            let community_feed =
                feed(format!("https://127.0.0.1:{alpha_port}"), "trust_feed").await?;
            let community_ring = community_feed["key_ring"].clone();
            // The community's identity: its founding fingerprint, verified from the genesis
            // document of its feed. Devices anchor their community trust to it (the vault of a
            // device-key member derives from it; the stamp scope is built from it).
            let genesis: Vec<u8> = serde_json::from_value(community_feed["genesis"].clone())
                .map_err(|_| "community genesis")?;
            let fingerprint = hex_encode(
                &csgn::verify_genesis(&genesis)
                    .map_err(|_| "community genesis")?
                    .fingerprint(),
            );
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
                    "fingerprint": fingerprint,
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
                    "timeout_seconds": 300,
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
            // A created community's Forum answers at `https://<community host>` (port 443).
            "forum": forum.is_some(),
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
    clock_task.abort();
    if let Some(mut forum) = forum {
        let _ = forum.kill();
        let _ = forum.wait();
    }
    drop(global);
    Ok(())
}

/// cfrm's own action names: `serve` refuses a throttle table that does not name exactly its
/// actions (cfrm `src/api.rs`, `actions!`).
const FORUM_ACTIONS: [&str; 21] = [
    "settings",
    "challenge",
    "enter",
    "replace",
    "heartbeat",
    "depart",
    "search",
    "watch",
    "ciphertext",
    "room_epoch",
    "room_issue",
    "room_list",
    "room_connect",
    "room_renew",
    "room_disconnect",
    "room_read",
    "room_order",
    "room_relay",
    "room_resume",
    "room_publish",
    "room_handover",
];

/// Start cfrm `serve` for every created community: communities come from the hub's registry
/// (`/registry/by-host`), each one's keys only from its own signed feed; native accounting
/// verifies record proofs with the same retained extension artifacts as the ledger. Only
/// public test values are written; diagnostics go to `service.stderr` in `dir`.
fn start_forum(
    bin: &std::path::Path,
    dir: &std::path::Path,
    listen: &str,
    registry: &str,
    root_der: &[u8],
) -> Result<std::process::Child> {
    let account_path = std::env::var_os("CVLD_G5_ACCOUNT_CONFIG").ok_or("G5 configuration")?;
    let account: serde_json::Value =
        serde_json::from_slice(&fs::read(account_path).map_err(|_| "G5 configuration")?)
            .map_err(|_| "G5 configuration decoding")?;
    let artifacts = &account["extension_artifacts"];
    let manifest = PathBuf::from(artifacts["manifest_file"].as_str().ok_or("manifest file")?);
    let directory = manifest.parent().ok_or("artifact directory")?;
    let execution = &account["update_execution"];
    let limits = &account["extension_limits"];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock")?
        .as_millis() as u64;
    let rate = json!({"burst": 1000, "replenish_ms": 100});
    let throttle: serde_json::Map<String, serde_json::Value> = FORUM_ACTIONS
        .iter()
        .map(|action| ((*action).to_owned(), rate.clone()))
        .collect();
    let config = json!({
        "bind": listen,
        "admission_action": cmty::ADMISSION_ACTION,
        "accounting": {
            "period_key": account["period_key"],
            // The toy Rulebook's record period (fixtures::accounting).
            "period_seconds": 86_400,
            "artifact_directory": directory,
            "manifest_sha256": artifacts["manifest_sha256"],
            "executable": execution["executable"],
            "timeout_ms": execution["timeout_ms"],
            "max_proof_bytes": execution["max_proof_bytes"],
            "threads": execution["threads"],
            "memory_megabytes": execution["memory_megabytes"],
            "global_burst": limits["global_burst"],
            "subject_burst": limits["subject_burst"],
            "replenish_ms": limits["replenish_ms"],
            "maximum_keys": limits["maximum_keys"],
        },
        // A fresh incarnation per start: a restart never reopens earlier volatile state.
        "incarnation": format!("toy-{}", hex_encode(&cpsd::rand::random::<[u8; 8]>())),
        "registry": {
            "url": format!("http://{registry}/registry"),
            "timeout_ms": 10_000,
            "recheck_seconds": 5,
            "sweep_seconds": 60,
            "maximum_communities": 64,
        },
        "trust_roots_der": [root_der],
        "refresh_seconds": 5,
        "poll_seconds": 5,
        "request_seconds": 30,
        "initial_backoff_seconds": 1,
        "maximum_backoff_seconds": 10,
        "maximum_staleness_seconds": 3_600,
        "maximum_snapshot_age": 3_600,
        "storage": {"kind": "memory"},
        "storage_limits": {
            "records": 65_536,
            "value_bytes": 1_048_576,
            "batch": 64,
            "indexes_per_record": 8,
            "page": 256,
            "ttl_ms": 86_400_000,
        },
        "maximum_lease_ms": 600_000,
        "publication_bytes": 262_144,
        "ciphertext_bytes": 262_144,
        "candidate_count": 64,
        "page_publication_bytes": 4_194_304,
        "room_epoch": {
            "epoch": 1,
            "valid_from_ms": now_ms.saturating_sub(3_600_000),
            "valid_until_ms": now_ms + 30 * 86_400_000,
        },
        "room_connections": 64,
        "room_relay_messages": 256,
        "room_message_bytes": 65_536,
        "room_lifetime_ms": 3_600_000,
        "room_proof_bytes": 8_192,
        "room_operation_receipts": 256,
        "request_bytes": 1_048_576,
        "http_concurrent": 64,
        "http_anonymous_concurrent": 16,
        "http_body_timeout_ms": 30_000,
        "http_request_timeout_ms": 300_000,
        "source_bucket": {"burst": 10_000, "replenish_ms": 10, "keys": 4_096},
        "session_bucket": {"burst": 10_000, "replenish_ms": 10, "keys": 4_096},
        "command_capacity": 256,
        "maintenance_ms": 1_000,
        "shutdown_ms": 5_000,
        "throttle_capacity": 4_096,
        "throttle": throttle,
    });
    // A continued state starts the Forum again with a fresh incarnation (it holds no durable state).
    fs::create_dir_all(dir).map_err(|_| "forum directory")?;
    let path = dir.join("config.json");
    fs::write(&path, serde_json::to_vec(&config).map_err(|_| "encode forum")?)
        .map_err(|_| "write forum configuration")?;
    std::process::Command::new(bin)
        .args(["serve", "--config"])
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(match fs::File::create(dir.join("service.stderr")) {
            Ok(file) => std::process::Stdio::from(file),
            Err(_) => std::process::Stdio::null(),
        })
        .spawn()
        .map_err(|_| "cannot start the forum".into())
}
