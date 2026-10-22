//! Composition, exact-host authorization and aggregate throttling.
use crate::{
    api::*,
    auth::{Auth, Grant},
    community::CommunityService,
    config::{CommunityConfig, Config},
    error::{Error, Result},
    global::GlobalService,
};
use axum::http::HeaderMap;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, watch};

mod account_record;
mod account_rotation;
mod account_tuning;
mod accounting;
mod bootstrap;
mod contacts;
mod creation;
pub use creation::CommunityHub;
mod enrollment;
mod garden;
mod global_self_ban;
mod migrations;
mod payments;
pub(crate) mod publication;
mod root_board;
mod root_issuance;
mod wallet;
pub use root_issuance::RootBoardPurpose;
mod shutdown;
mod step_up;
pub use crate::accounting::NativeConstruction;
pub use migrations::{community_migrations, global_migrations};

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}
tokio::task_local! {
    static OPERATION_TIME: u64;
    static LIVE_TIME: ();
}
pub(crate) async fn at<T>(now: u64, operation: impl std::future::Future<Output = T>) -> T {
    OPERATION_TIME.scope(now, operation).await
}
pub(crate) fn operation_time(clock: &dyn Clock) -> u64 {
    if LIVE_TIME.try_with(|_| ()).is_ok() {
        return clock.now();
    }
    OPERATION_TIME
        .try_with(|time| *time)
        .unwrap_or_else(|_| clock.now())
}
/// Lifecycle work without an original proof timestamp observes the live clock
/// through its own awaited owner calls. Ordinary proof composition stays bound
/// to OPERATION_TIME; this scope never changes a submitted proof's context.
pub(crate) async fn with_live_clock<T>(operation: impl std::future::Future<Output = T>) -> T {
    LIVE_TIME.scope((), operation).await
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
/// Most distinct (source, action) pairs tracked at once.
const SOURCE_KEYS: usize = 65_536;

fn source_buckets(
    burst: u32,
    interval_ms: u64,
) -> Result<crate::bucket::Keyed<(std::net::IpAddr, &'static str)>> {
    crate::bucket::Keyed::new(crate::bucket::Bucket {
        burst,
        replenish: Duration::from_millis(interval_ms),
        keys: SOURCE_KEYS,
    })
    .ok_or(Error::Invalid)
}

/// Anonymous ceremonies (registration, login, challenges) cost the most.
fn is_ceremony(action: &Action) -> bool {
    action.access == Access::Public
        && (action.name.ends_with("_begin")
            || action.name.ends_with("_finish")
            || action.name.starts_with("login_")
            || action.name == "presentation_challenge")
}

#[derive(Clone)]
pub struct Door {
    inner: Arc<Inner>,
}
struct Inner {
    /// Hosting hub of a multi-tenant global door; set once by the launcher.
    hub: Arc<std::sync::OnceLock<Arc<dyn CommunityHub>>>,
    requests: Arc<Mutex<()>>,
    ceremony_slots: Arc<Semaphore>,
    public_slots: Arc<Semaphore>,
    protected_slots: Arc<Semaphore>,
    watch_slots: Arc<Semaphore>,
    published: Published,
    scope: Scope,
    hosts: BTreeMap<String, Arc<Mutex<Auth>>>,
    backend: Backend,
    member_host: Option<String>,
    community_garden_host: Option<String>,
    root_board_admin_host: Option<String>,
    /// Per network source and action, RAM only: no global refusal.
    sources: crate::bucket::Keyed<(std::net::IpAddr, &'static str)>,
    proxies: crate::bucket::Proxies,
    clock: Arc<dyn Clock>,
    account_body_limit: usize,
    account_runtime: Option<Arc<crate::accounting::clock::AccountRuntime>>,
    account_shutdown: Option<cmty::cgts::AccountShutdown>,
    wallet_shutdown: Option<cgbl::WalletShutdown>,
    construction: Option<NativeConstruction>,
    ohttp: Option<crate::ohttp::Mounted>,
}
enum Published {
    Global(watch::Receiver<Arc<GlobalPublic>>),
    Community(watch::Receiver<Arc<TrustFeed>>),
}
enum Backend {
    Global(Box<Mutex<GlobalService>>),
    Community(Box<Mutex<CommunityService>>),
}
pub(crate) struct Context {
    pub host: String,
    pub grant: Option<Grant>,
    pub token: Option<String>,
    pub now: u64,
    pub authentication: Option<Arc<ckyh::Authentication>>,
}
impl Context {
    pub fn member(&self) -> Result<&ckyh::Authentication> {
        self.authentication.as_deref().ok_or(Error::Unauthorized)
    }

    /// The member for actions that by design need a human confirmation (device approval and
    /// revocation, lineage changes, step-ups). The ONE place that keeps device-key grants out of
    /// them; package 5 replaces it with a stamp check.
    pub fn human_member(&self) -> Result<&ckyh::Authentication> {
        self.member().and_then(|auth| {
            if auth.origin() == ckyh::Origin::Passkey {
                Ok(auth)
            } else {
                Err(Error::Unauthorized)
            }
        })
    }

    pub fn global_session(&self) -> Result<cgbl::Session> {
        cgbl::Session::authenticated(
            self.subject()?,
            self.grant.as_ref().ok_or(Error::Unauthorized)?.session_id,
        )
        .map_err(Error::Unauthorized.redact())
    }
    pub fn subject(&self) -> Result<cgbl::Subject> {
        cgbl::Subject::new(
            self.grant
                .as_ref()
                .ok_or(Error::Unauthorized)?
                .user
                .to_string(),
        )
        .map_err(Error::Invalid.redact())
    }
}
impl Door {
    /// Original constructed service kind, without exposing its retained owners.
    pub(crate) fn service_scope(&self) -> Scope {
        self.inner.scope
    }
    pub async fn global(config: Config, clock: Arc<dyn Clock>) -> Result<Self> {
        Self::global_with_optional_transport(config, clock, None).await
    }
    /// Trusted host injection replaces only external contact HTTP. It still
    /// requires real provider configuration, production mode, costs and policy.
    /// Member requests cannot supply a transport or construct verified facts.
    pub async fn global_with_contact_transport(
        config: Config,
        clock: Arc<dyn Clock>,
        transport: crate::contact_gates::transport::AnyTransport,
    ) -> Result<Self> {
        Self::global_with_optional_transport(config, clock, Some(transport)).await
    }
    async fn global_with_optional_transport(
        config: Config,
        clock: Arc<dyn Clock>,
        transport: Option<crate::contact_gates::transport::AnyTransport>,
    ) -> Result<Self> {
        config.shutdown_budget()?;
        if config.domain.is_empty()
            || !config
                .domain
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
            || config.publication_seconds < 172_800
            || !config.publication_seconds.is_multiple_of(86_400)
        {
            return Err(Error::Invalid);
        }
        let token = if let Some(path) = &config.database_token_file {
            String::from_utf8(Config::secret(path)?.to_vec()).map_err(Error::Invalid.redact())?
        } else {
            String::new()
        };
        let mut database = crlt::Config::new(&config.database_url, token);
        // Atomic mutations hold one lease while current-owner checks read the same database.
        database.max_connections = 2;
        let db = crlt::Db::open(database)
            .await
            .map_err(Error::Unavailable.redact())?;
        let now = clock.now();
        let mut global =
            GlobalService::open_with_transport(&db, &config, now, clock.clone(), transport).await?;
        let published = Published::Global(global.changes.subscribe());
        let mut hosts = BTreeMap::new();
        let wallet = format!("wallet.{}", config.domain);
        let root = format!("api.admin.root.{}", config.domain);
        for (host, role, scope, operator) in [
            (wallet, Role::Member, "wallet", None),
            (
                root,
                Role::Root,
                "root",
                Some(uuid::Uuid::parse_str(&config.root_user).map_err(Error::Invalid.redact())?),
            ),
        ] {
            let origins = if operator.is_some() {
                garden::operator_origins(&host)?
            } else {
                // The passkey ceremony runs in the vault frame on the vault origin;
                // the relying party stays the wallet host.
                vec![
                    ckyh::Url::parse(&format!("https://vault.{host}"))
                        .map_err(Error::Invalid.redact())?,
                ]
            };
            let passkeys = ckyh::Passkeys::new(
                ckyh::LibsqlStore::new(&db, scope, tokio::runtime::Handle::current())
                    .map_err(Error::Unavailable.redact())?,
                scope,
                host.strip_prefix("api.admin.").unwrap_or(&host),
                &origins,
            )
            .map_err(Error::Invalid.redact())?;
            let bootstrap = if operator.is_some() {
                config
                    .root_bootstrap_file
                    .as_ref()
                    .map(|path| {
                        Config::secret(path).and_then(|s| {
                            String::from_utf8(s.to_vec())
                                .map(zeroize::Zeroizing::new)
                                .map_err(Error::Invalid.redact())
                        })
                    })
                    .transpose()?
            } else {
                None
            };
            hosts.insert(
                host,
                Arc::new(Mutex::new(Auth::new(
                    passkeys,
                    role,
                    operator,
                    bootstrap,
                    config.pending_capacity,
                    config.session_seconds,
                )?)),
            );
        }
        let wallet_auth = hosts
            .get(&format!("wallet.{}", config.domain))
            .ok_or(Error::WrongHost)?;
        let wallet_keys = wallet_auth.lock().await.passkeys.clone();
        global
            .attach_wallet(&db, &config, wallet_keys, clock.now())
            .await?;
        let wallet_shutdown = global.wallet.as_ref().map(cgbl::Wallet::shutdown_handle);
        let sources = source_buckets(config.throttle_burst, config.throttle_interval_ms)?;
        let proxies = crate::bucket::Proxies::new(&config.trusted_proxies).ok_or(Error::Invalid)?;
        let names: Vec<String> = hosts.keys().cloned().collect();
        let hub_slot: Arc<std::sync::OnceLock<Arc<dyn CommunityHub>>> = Arc::new(std::sync::OnceLock::new());
        let ohttp = crate::ohttp::build(config.ohttp.as_ref(), &names, &db, "ohttp", Some(hub_slot.clone())).await?;
        Ok(Self {
            inner: Arc::new(Inner {
                requests: Arc::new(Mutex::new(())),
                ceremony_slots: Arc::new(Semaphore::new(16)),
                public_slots: Arc::new(Semaphore::new(32)),
                protected_slots: Arc::new(Semaphore::new(32)),
                watch_slots: Arc::new(Semaphore::new(16)),
                published,
                scope: Scope::Global,
                hub: hub_slot,
                hosts,
                backend: Backend::Global(Box::new(Mutex::new(global))),
                member_host: None,
                community_garden_host: None,
                root_board_admin_host: None,
                sources,
                proxies,
                clock,
                account_body_limit: 256 * 1024,
                account_runtime: None,
                construction: None,
                account_shutdown: None,
                wallet_shutdown,
                ohttp,
            }),
        })
    }
    /// Service maintenance uses only current state, without member activity logs.
    pub(crate) async fn request_guard(
        &self,
        action: &Action,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        if matches!(
            action.name,
            "global_public"
                | "account_checkpoint"
                | "trust_feed"
                | "trust_changes"
                | "wallet_trust_feed"
                | "wallet_trust_changes"
        ) {
            None
        } else {
            Some(self.inner.requests.clone().lock_owned().await)
        }
    }
    pub async fn maintain(&self) -> Result<()> {
        self.inner.sources.prune();
        let _guard = self.inner.requests.lock().await;
        let now = self.inner.clock.now();
        if let Backend::Community(community) = &self.inner.backend {
            return at(now, async { community.lock().await.maintain(now).await }).await;
        }
        let mut global = self.global_backend()?.lock().await;
        global
            .facade
            .prune_challenges(now, 100)
            .await
            .map_err(Error::Unavailable.redact())?;
        let fresh = global
            .facade
            .key_ring()
            .map_err(Error::Unavailable.redact())?
            .verify(&global.public.status, csgn::Kind::SettingsSnapshot, now)
            .map(|s| s.valid_until() > now + global.publication_seconds / 2)
            .unwrap_or(false);
        if !fresh {
            global.refresh(now).await?;
        }
        Ok(())
    }
    pub(crate) fn community_backend(&self) -> Result<&Mutex<CommunityService>> {
        match &self.inner.backend {
            Backend::Community(service) => Ok(service),
            _ => Err(Error::WrongHost),
        }
    }
    fn global_backend(&self) -> Result<&Mutex<GlobalService>> {
        match &self.inner.backend {
            Backend::Global(service) => Ok(service),
            _ => Err(Error::WrongHost),
        }
    }
    pub async fn community(config: CommunityConfig, clock: Arc<dyn Clock>) -> Result<Self> {
        Self::community_with_construction(config, clock, NativeConstruction::new()).await
    }
    /// Retain this construction owner before polling the factory. Its shutdown
    /// must complete before the original runtime is torn down after cancellation.
    pub async fn community_with_construction(
        config: CommunityConfig,
        clock: Arc<dyn Clock>,
        construction: NativeConstruction,
    ) -> Result<Self> {
        Self::community_with_optional_payment_transport(config, clock, None, None, construction)
            .await
    }
    /// Trusted host injection replaces only x402 protocol transport. It does
    /// not bypass real account, cost, policy, session or mode configuration.
    pub async fn community_with_payment_transport(
        config: CommunityConfig,
        clock: Arc<dyn Clock>,
        transport: crate::payments::transport::AnyTransport,
    ) -> Result<Self> {
        Self::community_with_optional_payment_transport(
            config,
            clock,
            Some(transport),
            None,
            NativeConstruction::new(),
        )
        .await
    }
    async fn community_with_optional_payment_transport(
        config: CommunityConfig,
        clock: Arc<dyn Clock>,
        transport: Option<crate::payments::transport::AnyTransport>,
        root_board: Option<cpsd::RootBoardPublicKey>,
        construction: NativeConstruction,
    ) -> Result<Self> {
        config.shutdown_budget()?;
        if config.domain.is_empty()
            || !config
                .domain
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
            || config.publication_seconds < 172_800
            || !config.publication_seconds.is_multiple_of(86_400)
        {
            return Err(Error::Invalid);
        }
        bootstrap::validate_operators(&config)?;
        let token = if let Some(path) = &config.database_token_file {
            String::from_utf8(Config::secret(path)?.to_vec()).map_err(Error::Invalid.redact())?
        } else {
            String::new()
        };
        let mut database = crlt::Config::new(&config.database_url, token);
        // Atomic mutations hold one lease while current-owner checks read the same database.
        database.max_connections = 2;
        let db = crlt::Db::open(database)
            .await
            .map_err(Error::Unavailable.redact())?;
        let mut hosts = BTreeMap::new();
        let member_host = format!("api.{}.{}", config.community, config.domain);
        let root_board_admin_host = root_board
            .as_ref()
            .map(|_| format!("api.admin.{}.{}", config.community, config.domain));
        let community = match root_board {
            Some(descriptor) => {
                CommunityService::open_root_board(
                    &db,
                    config,
                    clock.clone(),
                    descriptor,
                    transport,
                    construction.clone(),
                )
                .await?
            }
            None => {
                CommunityService::open_selected(
                    &db,
                    config,
                    clock.clone(),
                    transport,
                    None,
                    construction.clone(),
                )
                .await?
            }
        };
        let published = Published::Community(community.changes.subscribe());
        let account_body_limit = community.account_body_limit();
        let account_runtime = community.account_runtime();
        let account_shutdown = community.account_shutdown()?;
        let clock = community.account_clock().unwrap_or(clock);
        let startup = crate::accounting::startup::Startup::new(
            account_runtime.clone(),
            account_shutdown.clone(),
        );
        let result = async {
            let config = &community.config;
            let community_garden_host = format!("api.admin.{}.{}", config.community, config.domain);
            let operators = match &root_board_admin_host {
                // The ROOT garden uses actual ROOT memberships. A configured
                // platform operator cannot authenticate on that same host.
                Some(_) => vec![],
                None => vec![(
                    format!("api.admin.root.{}", config.domain),
                    Role::Root,
                    "operator:root",
                    &config.root,
                )],
            };
            for (host, role, scope, operator) in operators {
                let passkeys = ckyh::Passkeys::new(
                    ckyh::LibsqlStore::new(&db, scope, tokio::runtime::Handle::current())
                        .map_err(Error::Unavailable.redact())?,
                    scope,
                    host.strip_prefix("api.admin.").unwrap_or(&host),
                    &garden::operator_origins(&host)?,
                )
                .map_err(Error::Invalid.redact())?;
                let bootstrap = operator
                    .bootstrap_file
                    .as_ref()
                    .map(|path| {
                        Config::secret(path).and_then(|s| {
                            String::from_utf8(s.to_vec())
                                .map(zeroize::Zeroizing::new)
                                .map_err(Error::Invalid.redact())
                        })
                    })
                    .transpose()?;
                hosts.insert(
                    host,
                    Arc::new(Mutex::new(Auth::new(
                        passkeys,
                        role,
                        Some(
                            uuid::Uuid::parse_str(&operator.user)
                                .map_err(Error::Invalid.redact())?,
                        ),
                        bootstrap,
                        config.pending_capacity,
                        config.session_seconds,
                    )?)),
                );
            }
            let sources = source_buckets(config.throttle_burst, config.throttle_interval_ms)?;
            let proxies =
                crate::bucket::Proxies::new(&config.trusted_proxies).ok_or(Error::Invalid)?;
            let names: Vec<String> = hosts.keys().cloned().collect();
            let ohttp =
                crate::ohttp::build(config.ohttp.as_ref(), &names, &db, &config.community, None).await?;
            Ok(Self {
                inner: Arc::new(Inner {
                    hub: Arc::new(std::sync::OnceLock::new()),
                    requests: Arc::new(Mutex::new(())),
                    ceremony_slots: Arc::new(Semaphore::new(16)),
                    public_slots: Arc::new(Semaphore::new(32)),
                    protected_slots: Arc::new(Semaphore::new(32)),
                    watch_slots: Arc::new(Semaphore::new(16)),
                    published,
                    scope: Scope::Community,
                    hosts,
                    backend: Backend::Community(Box::new(Mutex::new(community))),
                    member_host: Some(member_host),
                    community_garden_host: Some(community_garden_host),
                    root_board_admin_host,
                    sources,
                    proxies,
                    clock,
                    account_body_limit,
                    account_runtime,
                    construction: Some(construction),
                    account_shutdown,
                    wallet_shutdown: None,
                    ohttp,
                }),
            })
        }
        .await;
        startup.finish(result).await
    }
    pub(crate) fn request_body_limit(&self, action: &Action) -> usize {
        if matches!(action.name, "account" | "account_enroll" | "pin_change") {
            self.inner.account_body_limit
        } else {
            256 * 1024
        }
    }
    pub(crate) fn allows_origin(&self, host: &str, origin: &str) -> bool {
        // Calls to the global wallet host come from the vault frame, so its only
        // allowed page origin is `https://vault.<wallet host>`.
        let direct = if host.starts_with("wallet.") && self.inner.hosts.contains_key(host) {
            format!("https://vault.{host}")
        } else {
            format!("https://{host}")
        };
        (self.inner.hosts.contains_key(host) || self.is_membership_host(host))
            && (origin == direct
                || ((self.inner.hosts.contains_key(host) || self.is_garden(host))
                    && host.strip_prefix("api.admin.").is_some_and(|canonical| {
                        origin == format!("https://admin.{canonical}")
                            || origin == format!("https://vault.{canonical}")
                    }))
                || (self.inner.member_host.as_deref() == Some(host)
                    && host.strip_prefix("api.").is_some_and(|canonical| {
                        origin == format!("https://{canonical}")
                            || origin == format!("https://vault.{canonical}")
                    })))
    }
    pub(crate) fn cors(&self) -> tower_http::cors::CorsLayer {
        use axum::http::{Method, header};
        use tower_http::cors::{AllowOrigin, CorsLayer};
        let door = self.clone();
        CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(move |origin, request| {
                request
                    .headers
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .zip(origin.to_str().ok())
                    .is_some_and(|(host, origin)| door.allows_origin(host, origin))
            }))
            .allow_methods([Method::POST, Method::GET])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(Duration::from_secs(600))
    }
    pub(crate) fn is_community_member(&self, host: &str) -> bool {
        self.inner.member_host.as_deref() == Some(host)
    }
    pub(crate) fn is_garden(&self, host: &str) -> bool {
        self.inner.community_garden_host.as_deref() == Some(host)
    }
    pub(crate) fn is_membership_host(&self, host: &str) -> bool {
        self.is_community_member(host) || self.is_garden(host)
    }
    pub(crate) fn auth(&self, host: &str) -> Result<Arc<Mutex<Auth>>> {
        self.inner.hosts.get(host).cloned().ok_or(Error::WrongHost)
    }
    pub(crate) async fn complete_context(
        &self,
        action: &Action,
        mut ctx: Context,
    ) -> Result<Context> {
        ctx.now = self.current_time(&ctx)?;
        // Body receipt and queue waits cannot preserve a logged-out, expired or
        // revoked grant. Recheck the exact credential at execution time.
        if !matches!(
            action.name,
            "global_public"
                | "trust_feed"
                | "trust_changes"
                | "account_checkpoint"
                | "wallet_trust_feed"
                | "wallet_trust_changes"
                | "login_begin"
                | "login_discoverable_begin"
                | "login_finish"
        ) && let Some(token) = &ctx.token
        {
            if self.is_membership_host(&ctx.host) {
                let mut community = self.community_backend()?.lock().await;
                ctx.now = self.current_time(&ctx)?;
                let (grant, authentication) = if self.is_garden(&ctx.host) {
                    community.authenticate_garden(token, ctx.now).await?
                } else {
                    community.authenticate(token, ctx.now).await?
                };
                // Default held: only actions declared `lobby` run for a member
                // who has not passed the gates now in force.
                if action.access == Access::Member && !action.lobby && !self.is_garden(&ctx.host) {
                    community.refuse_if_held(&authentication, ctx.now).await?;
                }
                ctx.grant = Some(grant);
                ctx.authentication = Some(authentication);
            } else {
                let auth = self.auth(&ctx.host)?;
                let mut auth = auth.lock().await;
                ctx.now = self.current_time(&ctx)?;
                ctx.grant = Some(auth.authenticate(token, ctx.now).await?);
            }
        }
        ctx.now = self.current_time(&ctx)?;
        Ok(ctx)
    }
    fn current_time(&self, ctx: &Context) -> Result<u64> {
        let now = self.inner.clock.now();
        if now < ctx.now || ctx.grant.as_ref().is_some_and(|grant| now >= grant.expires) {
            return Err(Error::Unauthorized);
        }
        Ok(now)
    }
    pub(crate) fn publication(&self, action: &Action, ctx: &Context) -> publication::Publication {
        publication::Publication::new(self.inner.clock.clone(), ctx, action.effect)
    }
    /// Slow anonymous clients are cut off sooner than authenticated ones.
    pub(crate) fn body_timeout(&self, action: &Action) -> Duration {
        if action.access == Access::Public {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(10)
        }
    }
    /// The network source of a request, honouring only configured proxies.
    pub(crate) fn source(&self, request: &axum::extract::Request) -> std::net::IpAddr {
        crate::bucket::source(request, &self.inner.proxies)
    }
    /// The network source of a request, or none when an Oblivious HTTP gateway
    /// unwrapped it: the peer is then the relay and carries no per-source limit.
    pub(crate) fn source_of_request(
        &self,
        request: &axum::extract::Request,
    ) -> Option<std::net::IpAddr> {
        (!crate::ohttp::via(request)).then(|| self.source(request))
    }
    pub(crate) fn ohttp(&self) -> Option<&crate::ohttp::Mounted> {
        self.inner.ohttp.as_ref()
    }
    #[cfg(all(test, feature = "development-gate"))]
    pub(crate) async fn admit_request(
        &self,
        action: &Action,
        source: std::net::IpAddr,
    ) -> Result<OwnedSemaphorePermit> {
        self.admit_source(action, Some(source)).await
    }
    pub(crate) async fn admit_source(
        &self,
        action: &Action,
        source: Option<std::net::IpAddr>,
    ) -> Result<OwnedSemaphorePermit> {
        // One source can exhaust only its own bucket for an action; a full key
        // table degrades to a shared overflow bucket, never a global refusal.
        if let Some(source) = source
            && !self.inner.sources.admit(&(source, action.name))
        {
            return Err(Error::Throttled);
        }
        let slots = if action.name == "trust_changes" {
            &self.inner.watch_slots
        } else if is_ceremony(action) {
            &self.inner.ceremony_slots
        } else if action.access == Access::Public {
            &self.inner.public_slots
        } else {
            &self.inner.protected_slots
        };
        slots
            .clone()
            .try_acquire_owned()
            .map_err(Error::Throttled.redact())
    }
    pub(crate) async fn authorize(&self, action: &Action, headers: &HeaderMap) -> Result<Context> {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::WrongHost)?
            .to_owned();
        let community_member = self.is_membership_host(&host);
        if !community_member && !self.inner.hosts.contains_key(&host) {
            return Err(Error::WrongHost);
        }
        if action.scope != Scope::Both && action.scope != self.inner.scope {
            return Err(Error::WrongHost);
        }
        if let Some(origin) = headers.get("origin")
            && !origin
                .to_str()
                .ok()
                .is_some_and(|origin| self.allows_origin(&host, origin))
        {
            return Err(Error::Forbidden);
        }
        let now = self.inner.clock.now();
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned);
        // Public metadata and dedicated outcome inspection do not consume a
        // login session. Status inspection verifies its own fresh passkey proof,
        // including when the caller still holds an ended membership's token.
        let token = if matches!(
            action.name,
            "global_public"
                | "trust_feed"
                | "trust_changes"
                | "account_checkpoint"
                | "wallet_trust_feed"
                | "wallet_trust_changes"
                | "community_self_ban_status_begin"
                | "community_self_ban_status_finish"
                // A sign-in ceremony starts a new session: a held token of an ended, expired or banned
                // one must not block it.
                | "login_begin"
                | "login_discoverable_begin"
                | "login_finish"
        ) {
            None
        } else {
            token
        };
        let (grant, authentication) = if let Some(token) = &token {
            if community_member {
                let mut community = self.community_backend()?.lock().await;
                let (grant, authentication) = if self.is_garden(&host) {
                    community.authenticate_garden(token, now).await?
                } else {
                    community.authenticate(token, now).await?
                };
                (Some(grant), Some(authentication))
            } else {
                (
                    Some(
                        self.auth(&host)?
                            .lock()
                            .await
                            .authenticate(token, now)
                            .await?,
                    ),
                    None,
                )
            }
        } else {
            (None, None)
        };
        let allowed = match action.access {
            Access::Public => true,
            access => {
                let grant = grant.as_ref().ok_or(Error::Unauthorized)?;
                match access {
                    Access::Authenticated => true,
                    Access::Member => grant.role == Role::Member,
                    Access::Admin => {
                        grant.role == Role::Admin
                            || (grant.role == Role::Root && self.is_garden(&host))
                    }
                    Access::Root => {
                        grant.role == Role::Root
                            && (!self.is_garden(&host)
                                || self.inner.root_board_admin_host.as_deref()
                                    == Some(host.as_str()))
                    }
                    Access::Public => true,
                }
            }
        };
        if !allowed {
            return Err(Error::Forbidden);
        }
        Ok(Context {
            host,
            grant,
            token,
            now,
            authentication,
        })
    }
    pub(crate) async fn register_begin(
        &self,
        ctx: Context,
        request: RegisterStart,
    ) -> Result<Ceremony> {
        if self.is_garden(&ctx.host) {
            return Err(Error::Forbidden);
        }
        if self.inner.member_host.as_deref() == Some(ctx.host.as_str()) {
            return self
                .community_backend()?
                .lock()
                .await
                .register_begin(request, ctx.now)
                .await;
        }
        self.auth(&ctx.host)?
            .lock()
            .await
            .register_begin(request, ctx.now)
            .await
    }
    pub(crate) async fn register_finish(
        &self,
        ctx: Context,
        request: RegisterFinish,
    ) -> Result<Registered> {
        if self.is_garden(&ctx.host) {
            return Err(Error::Forbidden);
        }
        let plain = |user: User| Registered {
            user: user.user,
            session: None,
        };
        if self.inner.member_host.as_deref() == Some(ctx.host.as_str()) {
            return self
                .community_backend()?
                .lock()
                .await
                .register_finish(request, ctx.now)
                .await
                .map(plain);
        }
        if self.inner.scope == Scope::Global {
            return self.wallet_register_finish(ctx, request).await;
        }
        self.auth(&ctx.host)?
            .lock()
            .await
            .register_finish_live(request, ctx.now, self.inner.clock.as_ref())
            .await
            .map(plain)
    }
    pub(crate) async fn login_begin(&self, ctx: Context, request: LoginStart) -> Result<Ceremony> {
        if self.is_membership_host(&ctx.host) {
            let mut community = self.community_backend()?.lock().await;
            return if self.is_garden(&ctx.host) {
                community.login_begin_for(request, ctx.now, true).await
            } else {
                community.login_begin(request, ctx.now).await
            };
        }
        self.auth(&ctx.host)?
            .lock()
            .await
            .login_begin(request, ctx.now)
            .await
    }
    pub(crate) async fn login_discoverable_begin(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<DiscoverableCeremony> {
        if self.is_membership_host(&ctx.host) {
            let mut community = self.community_backend()?.lock().await;
            return if self.is_garden(&ctx.host) {
                community.login_discoverable_begin_for(ctx.now, true).await
            } else {
                community.login_discoverable_begin(ctx.now).await
            };
        }
        self.auth(&ctx.host)?
            .lock()
            .await
            .login_discoverable_begin(ctx.now)
            .await
    }
    pub(crate) async fn login_finish(&self, ctx: Context, request: LoginFinish) -> Result<Session> {
        if self.is_membership_host(&ctx.host) {
            let mut community = self.community_backend()?.lock().await;
            return if self.is_garden(&ctx.host) {
                community.login_finish_for(request, ctx.now, true).await
            } else {
                community.login_finish(request, ctx.now).await
            };
        }
        if self.inner.scope == Scope::Global {
            return self.wallet_login_finish(ctx, request).await;
        }
        self.auth(&ctx.host)?
            .lock()
            .await
            .login_finish(request, ctx.now)
            .await
    }
    pub(crate) async fn logout(&self, ctx: Context, _: Empty) -> Result<Empty> {
        if self.is_membership_host(&ctx.host) {
            self.community_backend()?
                .lock()
                .await
                .logout(ctx.token.as_deref().ok_or(Error::Unauthorized)?);
            return Ok(Empty {});
        }
        self.auth(&ctx.host)?
            .lock()
            .await
            .logout(ctx.token.as_deref().ok_or(Error::Unauthorized)?);
        Ok(Empty {})
    }
    pub(crate) async fn global_public(&self, _: Context, _: Empty) -> Result<GlobalPublic> {
        match &self.inner.published {
            Published::Global(public) => Ok(public.borrow().as_ref().clone()),
            _ => Err(Error::WrongHost),
        }
    }
    pub(crate) fn community_public(&self) -> Result<watch::Receiver<Arc<TrustFeed>>> {
        match &self.inner.published {
            Published::Community(public) => Ok(public.clone()),
            _ => Err(Error::WrongHost),
        }
    }
    pub(crate) async fn passport_challenge(&self, ctx: Context, _: Empty) -> Result<Bytes> {
        let global = self.global_backend()?.lock().await;
        let challenge = global
            .facade
            .challenge(
                &mut cpsd::rand::rngs::OsRng,
                &ctx.global_session()?,
                ctx.now,
                ctx.now + 60,
            )
            .await
            .map_err(Error::Refused.redact())?;
        Ok(Bytes {
            bytes: challenge.to_bytes().to_vec(),
        })
    }
    pub(crate) async fn stamp_challenge(&self, ctx: Context, _: Empty) -> Result<StampChallenge> {
        let global = self.global_backend()?.lock().await;
        let (challenge, key) = global
            .facade
            .stamp_challenge(
                &mut cpsd::rand::rngs::OsRng,
                &ctx.global_session()?,
                ctx.now,
            )
            .await
            .map_err(Error::Refused.redact())?;
        drop(global);
        let options = serde_json::to_value(self.wallet_credential(&ctx).await?.request([0; 32]))
            .map_err(Error::Unavailable.redact())?;
        Ok(StampChallenge {
            challenge: challenge.to_bytes().to_vec(),
            key: key.to_bytes(),
            options,
        })
    }
    /// The registered passkey of this wallet session, as public verification material.
    async fn wallet_credential(&self, ctx: &Context) -> Result<ckyh::lineage::PublicCredential> {
        let grant = ctx.grant.as_ref().ok_or(Error::Unauthorized)?;
        let auth = self.auth(&ctx.host)?;
        let auth = auth.lock().await;
        let passkeys = auth.passkeys.clone();
        let (user, credential) = (grant.user, grant.credential.clone());
        tokio::task::spawn_blocking(move || passkeys.registered_public_credential(user, &credential))
            .await
            .map_err(Error::Unavailable.redact())?
            .map_err(Error::Unauthorized.redact())
    }
    /// The one human confirmation of a stamp: a user-verifying assertion of THIS session's
    /// wallet passkey whose WebAuthn challenge is exactly the request's confirmation challenge.
    /// Only after that verification does the wallet hand the challenge to cgbl.
    pub(crate) async fn stamp_issue(&self, ctx: Context, request: StampIssue) -> Result<Bytes> {
        let challenge = cpsd::IssuanceChallenge::from_bytes(
            request
                .challenge
                .try_into()
                .map_err(Error::Invalid.redact())?,
        );
        let stamp_request = cpsd::StampIssuanceRequest::from_bytes(&request.request)
            .map_err(Error::Invalid.redact())?;
        // The SAME request again (a device killed after the reply, before it stored the
        // stamp): the same stamp, no new user verification, no budget charge.
        if let Some(blind) = self
            .global_backend()?
            .lock()
            .await
            .facade
            .replay_stamp(&ctx.global_session()?, &stamp_request, ctx.now)
            .await
            .map_err(Error::Refused.redact())?
        {
            return Ok(Bytes {
                bytes: blind.to_bytes(),
            });
        }
        // The birth stamp (C5): no assertion, the birth grant instead. This Auth stays locked
        // until the stamp is issued; cgbl writes the first-only item with the budget charge.
        let Some(assertion) = request.assertion else {
            let token = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
            let authentication = self.auth(&ctx.host)?;
            let mut auth = authentication.lock().await;
            auth.birth_grant(token, self.inner.clock.now()).await?;
            let global = self.global_backend()?.lock().await;
            let blind = global
                .facade
                .issue_birth_stamp(
                    &mut cpsd::rand::rngs::OsRng,
                    &ctx.global_session()?,
                    &stamp_request,
                    &challenge,
                    ctx.now,
                )
                .await
                .map_err(Error::Refused.redact())?;
            return Ok(Bytes {
                bytes: blind.to_bytes(),
            });
        };
        let confirmation = stamp_request.confirmation_challenge(&challenge);
        let descriptor = self.wallet_credential(&ctx).await?;
        let assertion = ckyh::lineage::Assertion {
            credential_id: assertion.credential_id,
            client_data_json: assertion.client_data_json,
            authenticator_data: assertion.authenticator_data,
            signature: assertion.signature,
            user_handle: assertion.user_handle,
        };
        ckyh::lineage::verify(&descriptor, &assertion, confirmation)
            .map_err(Error::Unauthorized.redact())?;
        let global = self.global_backend()?.lock().await;
        let blind = global
            .facade
            .issue_stamp(
                &mut cpsd::rand::rngs::OsRng,
                &ctx.global_session()?,
                &stamp_request,
                &challenge,
                confirmation,
                ctx.now,
            )
            .await
            .map_err(Error::Refused.redact())?;
        Ok(Bytes {
            bytes: blind.to_bytes(),
        })
    }
    pub(crate) async fn passport_issue(
        &self,
        ctx: Context,
        request: PassportIssue,
    ) -> Result<Bytes> {
        let challenge = cpsd::IssuanceChallenge::from_bytes(
            request
                .challenge
                .try_into()
                .map_err(Error::Invalid.redact())?,
        );
        let birth_signature = request
            .birth_signature
            .map(|signature| <[u8; 64]>::try_from(signature).map_err(|_| Error::Invalid))
            .transpose()?;
        let request =
            cpsd::IssuanceRequest::from_bytes(&request.request).map_err(Error::Invalid.redact())?;
        // The birth passport (Q5): bound to the birth device K, first-only, under the birth
        // grant; this Auth stays locked until it is issued.
        if let Some(signature) = birth_signature {
            let token = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
            let authentication = self.auth(&ctx.host)?;
            let mut auth = authentication.lock().await;
            auth.birth_grant(token, self.inner.clock.now()).await?;
            let global = self.global_backend()?.lock().await;
            let passport = global
                .facade
                .issue_birth_passport(
                    &mut cpsd::rand::rngs::OsRng,
                    &ctx.global_session()?,
                    &challenge,
                    &request,
                    &signature,
                    ctx.now,
                )
                .await
                .map_err(Error::Refused.redact())?;
            return Ok(Bytes {
                bytes: passport.to_bytes(),
            });
        }
        let global = self.global_backend()?.lock().await;
        let passport = global
            .facade
            .issue_with_deadline_guard(
                &mut cpsd::rand::rngs::OsRng,
                &ctx.global_session()?,
                &challenge,
                &request,
                ctx.now,
                |deadline| {
                    let until = deadline
                        .inclusive()
                        .checked_add(1)
                        .ok_or(cgbl::Error::Challenge)?;
                    publication::expires_at(until).map_err(|_| cgbl::Error::Challenge)
                },
            )
            .await
            .map_err(Error::Refused.redact())?;
        Ok(Bytes {
            bytes: passport.to_bytes(),
        })
    }
    #[cfg(feature = "development-gate")]
    pub(crate) async fn development_gate(&self, ctx: Context, _: Empty) -> Result<Empty> {
        let global = self.global_backend()?.lock().await;
        let subject = ctx.subject()?;
        let check = cgbl::CheckId::generate(&mut cpsd::rand::rngs::OsRng);
        global
            .facade
            .run_gate(
                &cgbl::development::DevelopmentGate::new(global.development_expiry),
                &subject,
                subject.as_str().as_bytes(),
                ctx.now,
                &check,
            )
            .await
            .map_err(Error::Refused.redact())?;
        Ok(Empty {})
    }
}

#[cfg(all(test, feature = "development-gate"))]
#[path = "service_tests.rs"]
mod tests;

#[cfg(all(test, feature = "development-gate"))]
#[path = "service/tests.rs"]
mod boundaries;
