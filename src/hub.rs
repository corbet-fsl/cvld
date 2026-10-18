//! Multi-tenant hosting of communities: creation, the claim gate, a Host-routing
//! front over every live community door, and ending. The registry and the shared
//! database are the only durable state; the door map is derived and rebuilt from
//! the registry at start (`restore`).
use crate::{
    accounting::{AccountingTerms, Activation},
    address::Reserved,
    api,
    community::creation::{CreationGate, Lifecycle, Terms},
    config::CreationPlan,
    creation_token::{self, Issuer, Store},
    error::{Error, Result},
    hosts::{Boxed, HostProvisioner, Hostnames},
    purge,
    registry::{Entry, Registry, State},
    service::{Clock, CommunityHub, Door},
};
use axum::{body::Body, http::Request, response::IntoResponse};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use subtle::ConstantTimeEq;

/// The platform Root portal host label (`api.admin.root.<base>`); a platform host, never a community.
pub const PLATFORM_ROOT_HOST: &str = "root";
use tokio::sync::RwLock;
use tower::ServiceExt;

/// Opens the door of one community incarnation from its derived founding seed.
pub trait Factory: Send + Sync {
    /// `activation` is the creator's accounting genesis proof, given once at
    /// creation; a reopened community finds what was stored with it.
    fn open<'a>(
        &'a self,
        address: &'a str,
        seed: [u8; 32],
        plan: Option<CreationPlan>,
        activation: Option<Activation>,
    ) -> Boxed<'a, Result<Door>>;
    /// What a device must prove before creating a community today; `None` when
    /// the platform runs without accounting.
    fn terms(&self, now: u64) -> Result<Option<AccountingTerms>>;
    /// Remove what was derived for a community that is gone. Idempotent.
    fn forget(&self, seed: [u8; 32]);
}

/// Receives the end-of-chain statement of an ended community; the platform feed lists it so
/// every member device deletes its local data. Idempotent per fingerprint.
pub trait EndedSink: Send + Sync {
    fn ended<'a>(&'a self, fingerprint: [u8; 32], dissolved: bool, at: u64)
    -> Boxed<'a, Result<()>>;
}

pub struct HubParts {
    /// The global service database: holds the registry and the token tables.
    pub global_db: crlt::Db,
    /// The shared community database: every community is a scope in it.
    pub community_db: crlt::Db,
    pub issuer: Issuer,
    pub limits: creation_token::Limits,
    pub provisioner: Arc<dyn HostProvisioner>,
    pub factory: Arc<dyn Factory>,
    /// The platform base domain, e.g. `cmtymeet.corbet.ch`.
    pub base: String,
    pub reserved: Reserved,
    pub clock: Arc<dyn Clock>,
    /// How long an unclaimed shell lives.
    pub shell_seconds: u64,
    /// Platform charter master secret; per-community seeds derive from it.
    pub master: zeroize::Zeroizing<Vec<u8>>,
}

struct Live {
    door: Door,
    router: axum::Router,
}

pub struct Hub {
    registry: Arc<Registry>,
    tokens: Store,
    issuer: Issuer,
    provisioner: Arc<dyn HostProvisioner>,
    factory: Arc<dyn Factory>,
    community_db: crlt::Db,
    base: String,
    reserved: Reserved,
    clock: Arc<dyn Clock>,
    shell_seconds: u64,
    master: zeroize::Zeroizing<Vec<u8>>,
    doors: RwLock<BTreeMap<String, Live>>,
    ended_sink: std::sync::OnceLock<Arc<dyn EndedSink>>,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn claim_hash(secret: &[u8]) -> [u8; 32] {
    Sha256::digest([b"cvld.claim.v1\0".as_slice(), secret].concat()).into()
}

/// Per-community founding seed: HKDF of the platform master secret and the
/// community's fresh random id, so a reused address gets a new key.
fn seed(master: &[u8], id: &[u8; 16]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b"cvld.community.founding.v1"), master)
        .expand(id, &mut out)
        .map_err(|_| Error::Unavailable)?;
    Ok(out)
}

/// A creation is a person's interrupted afternoon, not a request: a shell lives at
/// least this long, and every resume or claim extends it by the same time.
pub const MIN_SHELL_SECONDS: u64 = 7 * 86_400;

/// The claim secret is derived, so a creation that is repeated with the same token
/// is answered with the same secret and a device interrupted before it stored the
/// answer can still claim. Only the hash is kept in the registry.
fn claim_for(master: &[u8], id: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; 32];
    Hkdf::<Sha256>::new(Some(b"cvld.community.claim.v1"), master)
        .expand(id, &mut out)
        .map_err(|_| Error::Unavailable)?;
    Ok(out)
}

struct ShellGate {
    shell_seconds: u64,
    registry: Arc<Registry>,
    tokens: Arc<dyn Fn([u8; 16]) -> Boxed<'static, Result<()>> + Send + Sync>,
    id: [u8; 16],
}

impl CreationGate for ShellGate {
    fn check<'a>(&'a self, secret: &'a [u8], now: u64) -> Boxed<'a, Result<Terms>> {
        Box::pin(async move {
            let entry = self.registry.by_id(self.id).await?.ok_or(Error::Refused)?;
            let until = entry.expires_at.ok_or(Error::Refused)?;
            let fresh = entry.state == State::BeingCreated && now < until;
            let matches: bool = claim_hash(secret).ct_eq(&entry.claim_hash).into();
            if !(fresh && matches) {
                return Err(Error::Refused);
            }
            // The claimed seat waits for the admission as long as a creation may.
            let until = now.saturating_add(self.shell_seconds).max(until);
            self.registry.extend_shell(self.id, until).await?;
            Ok(Terms {
                id: hex(&self.id),
                valid_until: until,
            })
        })
    }
    fn completed<'a>(&'a self) -> Boxed<'a, Result<()>> {
        Box::pin(async move {
            self.registry.mark_live(self.id).await?;
            (self.tokens)(self.id).await
        })
    }
}

impl Hub {
    pub async fn new(parts: HubParts) -> Result<Arc<Self>> {
        parts
            .global_db
            .migrate(&crate::service::global_migrations())
            .await
            .map_err(Error::Unavailable.redact())?;
        parts
            .community_db
            .migrate(&crate::service::community_migrations())
            .await
            .map_err(Error::Unavailable.redact())?;
        if parts.master.len() < 32 {
            return Err(Error::Invalid);
        }
        let scope = parts
            .global_db
            .community("global")
            .map_err(Error::Invalid.redact())?;
        Ok(Arc::new(Self {
            registry: Arc::new(Registry::new(scope.clone())),
            tokens: Store::new(scope, parts.limits),
            issuer: parts.issuer,
            provisioner: parts.provisioner,
            factory: parts.factory,
            community_db: parts.community_db,
            base: parts.base,
            reserved: parts.reserved,
            clock: parts.clock,
            shell_seconds: parts.shell_seconds.max(MIN_SHELL_SECONDS),
            master: parts.master,
            doors: RwLock::new(BTreeMap::new()),
            ended_sink: std::sync::OnceLock::new(),
        }))
    }

    /// Where end-of-chain statements go. Done once, by the launcher.
    pub fn attach_ended_sink(&self, sink: Arc<dyn EndedSink>) -> Result<()> {
        self.ended_sink.set(sink).map_err(|_| Error::Forbidden)
    }

    /// Publish the end-of-chain statement of an ending community (once admitted, it has a
    /// fingerprint). Repeats are harmless; a failure keeps the community in `ending`.
    async fn publish_end(&self, entry: &Entry, now: u64) -> Result<()> {
        let (Some(fingerprint), Some(sink)) = (entry.fingerprint, self.ended_sink.get()) else {
            return Ok(());
        };
        let dissolved = entry.end_reason.as_deref() == Some("dissolved");
        sink.ended(fingerprint, dissolved, entry.ended_at.unwrap_or(now))
            .await
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    fn gate(self: &Arc<Self>, id: [u8; 16]) -> Arc<ShellGate> {
        let hub = self.clone();
        Arc::new(ShellGate {
            shell_seconds: self.shell_seconds,
            registry: self.registry.clone(),
            tokens: Arc::new(move |id| {
                let hub = hub.clone();
                Box::pin(async move { hub.tokens.spend(id).await })
            }),
            id,
        })
    }

    async fn install(self: &Arc<Self>, entry: &Entry, door: Door) {
        let _ = door
            .attach_lifecycle(Arc::new(Dissolve {
                hub: self.clone(),
                address: entry.address.clone(),
            }))
            .await;
        let router = api::router(door.clone());
        self.doors
            .write()
            .await
            .insert(entry.address.clone(), Live { door, router });
    }

    /// Reopen every serving community of the registry (process start).
    pub async fn restore(self: &Arc<Self>) -> Result<()> {
        let now = self.clock.now();
        for entry in self.registry.serving().await? {
            let seed = seed(&self.master, &entry.id)?;
            let door = self.factory.open(&entry.address, seed, None, None).await?;
            if entry.state == State::BeingCreated && now < entry.expires_at.unwrap_or(0) {
                door.attach_creation_gate(self.gate(entry.id)).await?;
            }
            self.install(&entry, door).await;
        }
        Ok(())
    }

    async fn rollback(&self, entry: &Entry) {
        if let Some(live) = self.doors.write().await.remove(&entry.address) {
            let _ = live.door.begin_shutdown_accounts();
            let _ = live.door.shutdown_accounts().await;
        }
        let _ = self
            .provisioner
            .deprovision(&Hostnames::new(&entry.address, &self.base))
            .await;
        let _ = purge::purge_scope(&self.community_db, &entry.address).await;
        let _ = self.tokens.release(entry.id).await;
        let _ = self.registry.remove_shell(entry.id).await;
        if let Ok(seed) = seed(&self.master, &entry.id) {
            self.factory.forget(seed);
        }
    }

    /// Expire abandoned shells; a shell whose creator already completed
    /// admission goes live instead.
    pub async fn sweep(self: &Arc<Self>) -> Result<()> {
        let now = self.clock.now();
        for entry in self.registry.due_for_deletion(now).await? {
            self.detach(&entry).await;
            self.finish(&entry, now).await?;
        }
        for entry in self.registry.expired_shells(now).await? {
            let admitted = match self.doors.read().await.get(&entry.address) {
                Some(live) => live.door.community_active().await.unwrap_or(false),
                None => false,
            };
            if admitted {
                self.registry.mark_live(entry.id).await?;
                self.tokens.spend(entry.id).await?;
            } else {
                self.rollback(&entry).await;
            }
        }
        Ok(())
    }

    /// End a community at once. Nothing is served from the moment the registry
    /// row says `ending`; hostnames go; the data is deleted as one step now, or
    /// when the hold ends.
    pub async fn end(
        self: &Arc<Self>,
        address: &str,
        reason: &str,
        hold_until: Option<u64>,
        block_name: bool,
        now: u64,
    ) -> Result<()> {
        let entry = self
            .registry
            .by_address(address, now)
            .await?
            .filter(|entry| entry.state.serves())
            .ok_or(Error::Refused)?;
        let entry = self
            .registry
            .begin_end(entry.id, now, reason, hold_until, block_name)
            .await?;
        self.detach(&entry).await;
        self.finish(&entry, now).await
    }

    /// Stop serving: close the door and remove the hostnames. Idempotent.
    async fn detach(&self, entry: &Entry) {
        if let Some(live) = self.doors.write().await.remove(&entry.address) {
            let _ = live.door.begin_shutdown_accounts();
            let _ = live.door.shutdown_accounts().await;
        }
        let _ = self
            .provisioner
            .deprovision(&Hostnames::new(&entry.address, &self.base))
            .await;
        let _ = self.tokens.release(entry.id).await;
    }

    /// Delete the data of an ending community once no hold applies.
    async fn finish(&self, entry: &Entry, now: u64) -> Result<()> {
        self.publish_end(entry, now).await?;
        if entry.hold_until.is_some_and(|until| until > now) {
            return Ok(());
        }
        self.provisioner
            .deprovision(&Hostnames::new(&entry.address, &self.base))
            .await?;
        purge::purge_scope(&self.community_db, &entry.address).await?;
        if let Ok(seed) = seed(&self.master, &entry.id) {
            self.factory.forget(seed);
        }
        self.registry.finish_end(entry.id).await
    }

    /// Route one request by Host to the global door or a community door.
    pub async fn dispatch(
        self: &Arc<Self>,
        global: axum::Router,
        request: Request<Body>,
    ) -> axum::response::Response {
        let host = request
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(':')
                    .next()
                    .unwrap_or(value)
                    .to_ascii_lowercase()
            });
        let Some(host) = host else {
            return Error::WrongHost.into_response();
        };
        let Some(suffix) = host
            .strip_suffix(&self.base)
            .and_then(|rest| rest.strip_suffix('.'))
        else {
            return Error::WrongHost.into_response();
        };
        let label = suffix
            .strip_prefix("api.admin.")
            .or_else(|| suffix.strip_prefix("api."));
        let router = match label {
            // "root" is the platform Root portal host, not a community: community
            // addresses have at least eight characters, so no community can collide.
            Some(address) if address != PLATFORM_ROOT_HOST => match self.doors.read().await.get(address) {
                Some(live) => live.router.clone(),
                None => return Error::WrongHost.into_response(),
            },
            // wallet.<base>, api.admin.<PLATFORM_ROOT_HOST>.<base> and every other global host.
            _ => global,
        };
        match router.oneshot(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        }
    }

    /// The front router: one listener for the global door and every community.
    pub fn front(self: &Arc<Self>, global: &Door) -> axum::Router {
        let hub = self.clone();
        let global = api::router(global.clone());
        axum::Router::new()
            .route("/registry/by-host", axum::routing::get(by_host))
            .route("/registry/finished", axum::routing::get(finished))
            .with_state(self.clone())
            .fallback(move |request: Request<Body>| {
                let hub = hub.clone();
                let global = global.clone();
                async move { hub.dispatch(global, request).await }
            })
    }

    /// Fence and join every dynamic door (process shutdown).
    pub async fn close(&self) -> Result<()> {
        let doors: Vec<Door> = self
            .doors
            .read()
            .await
            .values()
            .map(|live| live.door.clone())
            .collect();
        let mut failed = false;
        for door in &doors {
            failed |= door.begin_shutdown_accounts().is_err();
        }
        for door in &doors {
            failed |= door.shutdown_accounts().await.is_err();
        }
        if failed {
            Err(Error::Unavailable)
        } else {
            Ok(())
        }
    }

    /// Keep every dynamic door's own maintenance running.
    pub async fn maintain(self: &Arc<Self>) -> Result<()> {
        let doors: Vec<Door> = self
            .doors
            .read()
            .await
            .values()
            .map(|live| live.door.clone())
            .collect();
        for door in doors {
            door.maintain().await?;
        }
        self.sweep().await
    }
}

/// Lets a community's admins dissolve it through the hub.
struct Dissolve {
    hub: Arc<Hub>,
    address: String,
}

impl Lifecycle for Dissolve {
    fn dissolve<'a>(&'a self, now: u64) -> Boxed<'a, Result<()>> {
        Box::pin(async move {
            self.hub
                .end(&self.address, "dissolved", None, false, now)
                .await
        })
    }
}

impl CommunityHub for Arc<Hub> {
    fn serves_host<'a>(&'a self, host: &'a str) -> Boxed<'a, bool> {
        Box::pin(async move {
            matches!(
                self.registry.by_host(host, &self.base).await,
                Ok(Some((entry, _))) if entry.state == State::Live
            )
        })
    }
    fn terminate<'a>(
        &'a self,
        request: api::CommunityTerminate,
        now: u64,
    ) -> Boxed<'a, Result<()>> {
        Box::pin(async move {
            // A hold is only for legal orders.
            if request.hold_until.is_some() && request.reason != api::TerminationReason::Legal {
                return Err(Error::Invalid);
            }
            self.end(
                &request.address,
                request.reason.code(),
                request.hold_until,
                request.block_name,
                now,
            )
            .await
        })
    }

    fn create<'a>(
        &'a self,
        request: api::CommunityCreate,
        now: u64,
    ) -> Boxed<'a, Result<api::CommunityCreated>> {
        Box::pin(async move {
            let hub = self;
            // 1. Validate address and token before anything is created.
            crate::address::validate(&request.address, &hub.reserved)
                .map_err(|_| Error::Invalid)?;
            let plan = CreationPlan {
                display_name: request.display_name,
                gates: request.gates,
            };
            // With accounting every community needs its creator's genesis proof;
            // the factory verifies it against this community, never the hub's say-so.
            let owner = czkp::activation_owner(&request.address, &request.token.message);
            let activation = request.activation.map(|upload| Activation {
                statement: upload.statement,
                proof: upload.proof,
                owner,
            });
            if hub.factory.terms(now)?.is_some() && activation.is_none() {
                return Err(Error::Invalid);
            }
            plan.validate()?;
            let token: creation_token::Token = request.token.into();
            let nullifier = creation_token::verify(hub.issuer.public(), &token)?;
            // A repeat of an interrupted creation (same token, same address) is
            // answered from the shell that already exists: never a second community.
            if let Some((shell, spent)) = hub.tokens.reservation(nullifier).await? {
                let entry = hub.registry.by_id(shell).await?.ok_or(Error::Refused)?;
                let waiting = entry.state == State::BeingCreated
                    && !spent
                    && entry.address == request.address
                    && now < entry.expires_at.unwrap_or(0);
                let fingerprint = entry.fingerprint.ok_or(Error::Refused)?;
                if !waiting {
                    return Err(Error::Refused);
                }
                let until = now.saturating_add(hub.shell_seconds);
                hub.registry.extend_shell(shell, until).await?;
                let hosts = Hostnames::new(&entry.address, &hub.base);
                return Ok(api::CommunityCreated {
                    id: hex(&shell),
                    fingerprint: hex(&fingerprint),
                    community_host: hosts.community,
                    vault_host: hosts.vault,
                    claim: claim_for(&hub.master, &shell)?,
                    expires_at: until.max(entry.expires_at.unwrap_or(0)),
                });
            }
            // 2. Shell id, claim secret and founding seed.
            let mut id = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut id);
            let claim = claim_for(&hub.master, &id)?;
            let founding = seed(&hub.master, &id)?;
            // 3. Reserve the token, then register the shell (address uniqueness).
            hub.tokens.reserve(nullifier, id).await?;
            let entry = match hub
                .registry
                .create_shell(
                    id,
                    &request.address,
                    claim_hash(&claim),
                    now,
                    hub.shell_seconds,
                    &hub.reserved,
                )
                .await
            {
                Ok(entry) => entry,
                Err(error) => {
                    let _ = hub.tokens.release(id).await;
                    return Err(error);
                }
            };
            // 4..6. Open the community (creates its founding key and genesis),
            // register the fingerprint, provision hosts. Any failure rolls back.
            let built = async {
                let door = hub
                    .factory
                    .open(&entry.address, founding, Some(plan), activation)
                    .await?;
                let genesis = door.community_genesis().await?;
                let fingerprint = csgn::verify_genesis(&genesis)
                    .map_err(Error::Unavailable.redact())?
                    .fingerprint();
                hub.registry.set_fingerprint(id, fingerprint).await?;
                door.attach_creation_gate(hub.gate(id)).await?;
                hub.provisioner
                    .provision(&Hostnames::new(&entry.address, &hub.base))
                    .await?;
                Ok::<_, Error>((door, fingerprint))
            }
            .await;
            let (door, fingerprint) = match built {
                Ok(built) => built,
                Err(error) => {
                    hub.rollback(&entry).await;
                    return Err(error);
                }
            };
            hub.install(&entry, door).await;
            let hosts = Hostnames::new(&entry.address, &hub.base);
            Ok(api::CommunityCreated {
                id: hex(&id),
                fingerprint: hex(&fingerprint),
                community_host: hosts.community,
                vault_host: hosts.vault,
                claim,
                expires_at: entry.expires_at.unwrap_or(now),
            })
        })
    }

    fn terms<'a>(
        &'a self,
        request: api::CommunityTermsRequest,
        now: u64,
    ) -> Boxed<'a, Result<api::CommunityTerms>> {
        Box::pin(async move {
            crate::address::validate(&request.address, &self.reserved)
                .map_err(|_| Error::Invalid)?;
            Ok(api::CommunityTerms {
                accounting: self
                    .factory
                    .terms(now)?
                    .map(|terms| api::AccountingTermsWire {
                        standing: terms.standing,
                        observed_at: terms.observed_at,
                        ledger_policy: terms.ledger_policy,
                        extension_policy: terms.extension_policy,
                    }),
            })
        })
    }

    fn issue_token<'a>(
        &'a self,
        subject: &'a str,
        blinded: &'a [u8],
        now: u64,
    ) -> Boxed<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            // The same blinded message again (an interrupted device) gets the
            // same answer and no second count.
            if let Some(signature) = self.tokens.replay(subject, blinded).await? {
                return Ok(signature);
            }
            let signature = self.issuer.sign(blinded)?;
            self.tokens.record_issuance(subject, now).await?;
            self.tokens
                .remember(subject, blinded, &signature, now)
                .await?;
            Ok(signature)
        })
    }

    fn token_key(&self) -> Result<Vec<u8>> {
        self.issuer.public_der()
    }
}

/// The record the forum needs for one serving community. Keys are NOT served
/// here: they come from the community's signed feed, verified against the
/// fingerprint.
#[derive(serde::Serialize)]
struct Record {
    id: String,
    state: &'static str,
    origins: Vec<String>,
    trust_origin: String,
    fingerprint: String,
}

#[derive(serde::Deserialize)]
struct HostQuery {
    host: String,
}

#[derive(serde::Deserialize)]
struct SinceQuery {
    #[serde(default)]
    since: u64,
}

async fn by_host(
    axum::extract::State(hub): axum::extract::State<Arc<Hub>>,
    axum::extract::Query(query): axum::extract::Query<HostQuery>,
) -> axum::response::Response {
    let host = query.host.to_ascii_lowercase();
    let found = match hub.registry.by_host(&host, &hub.base).await {
        Ok(found) => found,
        Err(error) => return error.into_response(),
    };
    match found {
        Some((entry, _)) if entry.fingerprint.is_some() => {
            let hosts = Hostnames::new(&entry.address, &hub.base);
            let record = Record {
                id: hex(&entry.id),
                state: entry.state.code(),
                origins: vec![
                    format!("https://{}", hosts.community),
                    format!("https://{}", hosts.vault),
                ],
                trust_origin: format!("https://api.{}", hosts.community),
                fingerprint: hex(&entry.fingerprint.unwrap_or_default()),
            };
            (
                [(axum::http::header::CACHE_CONTROL, "no-store")],
                axum::Json(record),
            )
                .into_response()
        }
        _ => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

/// Ending and ended communities with a change counter above `since`. The newest
/// counter is returned in `x-registry-cursor`.
async fn finished(
    axum::extract::State(hub): axum::extract::State<Arc<Hub>>,
    axum::extract::Query(query): axum::extract::Query<SinceQuery>,
) -> axum::response::Response {
    match hub.registry.finished_since(query.since, 500).await {
        Ok(entries) => {
            let cursor = entries.iter().map(|e| e.seq).max().unwrap_or(query.since);
            let ids: Vec<String> = entries.iter().map(|e| hex(&e.id)).collect();
            (
                [
                    (axum::http::header::CACHE_CONTROL, "no-store".to_owned()),
                    (
                        axum::http::HeaderName::from_static("x-registry-cursor"),
                        cursor.to_string(),
                    ),
                ],
                axum::Json(ids),
            )
                .into_response()
        }
        Err(error) => error.into_response(),
    }
}
