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
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, watch};

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}
tokio::task_local! {
    static OPERATION_TIME: u64;
}
pub(crate) async fn at<T>(now: u64, operation: impl std::future::Future<Output = T>) -> T {
    OPERATION_TIME.scope(now, operation).await
}
pub(crate) fn operation_time(clock: &dyn Clock) -> u64 {
    OPERATION_TIME
        .try_with(|time| *time)
        .unwrap_or_else(|_| clock.now())
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
#[derive(Clone)]
pub struct Door {
    inner: Arc<Inner>,
}
struct Inner {
    requests: Arc<Mutex<()>>,
    public_slots: Arc<Semaphore>,
    protected_slots: Arc<Semaphore>,
    watch_slots: Arc<Semaphore>,
    published: Published,
    scope: Scope,
    hosts: BTreeMap<String, Arc<Mutex<Auth>>>,
    backend: Backend,
    member_host: Option<String>,
    throttle: cthl::Throttle<cthl::MemoryStore>,
    clock: Arc<dyn Clock>,
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
    pub authentication: Option<Arc<cpky::Authentication>>,
}
impl Context {
    pub fn member(&self) -> Result<&cpky::Authentication> {
        self.authentication.as_deref().ok_or(Error::Unauthorized)
    }

    pub fn global_session(&self) -> Result<cglb::Session> {
        cglb::Session::authenticated(
            self.subject()?,
            self.grant.as_ref().ok_or(Error::Unauthorized)?.session_id,
        )
        .map_err(|_| Error::Unauthorized)
    }
    pub fn subject(&self) -> Result<cglb::Subject> {
        cglb::Subject::new(
            self.grant
                .as_ref()
                .ok_or(Error::Unauthorized)?
                .user
                .to_string(),
        )
        .map_err(|_| Error::Invalid)
    }
}
impl Door {
    pub async fn global(config: Config, clock: Arc<dyn Clock>) -> Result<Self> {
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
            String::from_utf8(Config::secret(path)?.to_vec()).map_err(|_| Error::Invalid)?
        } else {
            String::new()
        };
        let db = crlt::Db::open(crlt::Config::new(&config.database_url, token))
            .await
            .map_err(|_| Error::Unavailable)?;
        let now = clock.now();
        let global = GlobalService::open(&db, &config, now).await?;
        let published = Published::Global(global.changes.subscribe());
        let mut hosts = BTreeMap::new();
        let wallet = format!("wallet.{}", config.domain);
        let root = format!("api.root.{}", config.domain);
        for (host, role, scope, operator) in [
            (wallet, Role::Member, "wallet", None),
            (
                root,
                Role::Root,
                "root",
                Some(uuid::Uuid::parse_str(&config.root_user).map_err(|_| Error::Invalid)?),
            ),
        ] {
            let passkeys = cpky::Passkeys::new(
                cpky::LibsqlStore::new(&db, scope, tokio::runtime::Handle::current())
                    .map_err(|_| Error::Unavailable)?,
                scope,
                &host,
                &[cpky::Url::parse(&format!("https://{host}")).map_err(|_| Error::Invalid)?],
            )
            .map_err(|_| Error::Invalid)?;
            let bootstrap = if operator.is_some() {
                config
                    .root_bootstrap_file
                    .as_ref()
                    .map(|path| {
                        Config::secret(path).and_then(|s| {
                            String::from_utf8(s.to_vec())
                                .map(zeroize::Zeroizing::new)
                                .map_err(|_| Error::Invalid)
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
        let limit = cthl::Limit::new(
            config.throttle_burst,
            Duration::from_millis(config.throttle_interval_ms),
        )
        .map_err(|_| Error::Invalid)?;
        let throttle = cthl::Throttle::new(
            "global",
            ACTIONS.iter().map(|a| (a.name, limit)),
            cthl::MemoryStore::new(NonZeroUsize::new(ACTIONS.len()).ok_or(Error::Invalid)?),
        )
        .map_err(|_| Error::Invalid)?;
        Ok(Self {
            inner: Arc::new(Inner {
                requests: Arc::new(Mutex::new(())),
                public_slots: Arc::new(Semaphore::new(32)),
                protected_slots: Arc::new(Semaphore::new(32)),
                watch_slots: Arc::new(Semaphore::new(16)),
                published,
                scope: Scope::Global,
                hosts,
                backend: Backend::Global(Box::new(Mutex::new(global))),
                member_host: None,
                throttle,
                clock,
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
            "global_public" | "trust_feed" | "trust_changes"
        ) {
            None
        } else {
            Some(self.inner.requests.clone().lock_owned().await)
        }
    }
    pub async fn maintain(&self) -> Result<()> {
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
            .map_err(|_| Error::Unavailable)?;
        let fresh = global
            .facade
            .key_ring()
            .map_err(|_| Error::Unavailable)?
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
            String::from_utf8(Config::secret(path)?.to_vec()).map_err(|_| Error::Invalid)?
        } else {
            String::new()
        };
        let db = crlt::Db::open(crlt::Config::new(&config.database_url, token))
            .await
            .map_err(|_| Error::Unavailable)?;
        let mut hosts = BTreeMap::new();
        let member_host = format!("api.{}.{}", config.community, config.domain);
        let community = CommunityService::open(&db, config, clock.clone()).await?;
        let published = Published::Community(community.changes.subscribe());
        let config = &community.config;
        for (host, role, scope, operator) in [
            (
                format!("api.admin.{}.{}", config.community, config.domain),
                Role::Admin,
                "operator:admin",
                &config.admin,
            ),
            (
                format!("api.root.{}", config.domain),
                Role::Root,
                "operator:root",
                &config.root,
            ),
        ] {
            let passkeys = cpky::Passkeys::new(
                cpky::LibsqlStore::new(&db, scope, tokio::runtime::Handle::current())
                    .map_err(|_| Error::Unavailable)?,
                scope,
                &host,
                &[cpky::Url::parse(&format!("https://{host}")).map_err(|_| Error::Invalid)?],
            )
            .map_err(|_| Error::Invalid)?;
            let bootstrap = operator
                .bootstrap_file
                .as_ref()
                .map(|path| {
                    Config::secret(path).and_then(|s| {
                        String::from_utf8(s.to_vec())
                            .map(zeroize::Zeroizing::new)
                            .map_err(|_| Error::Invalid)
                    })
                })
                .transpose()?;
            hosts.insert(
                host,
                Arc::new(Mutex::new(Auth::new(
                    passkeys,
                    role,
                    Some(uuid::Uuid::parse_str(&operator.user).map_err(|_| Error::Invalid)?),
                    bootstrap,
                    config.pending_capacity,
                    config.session_seconds,
                )?)),
            );
        }
        let limit = cthl::Limit::new(
            config.throttle_burst,
            Duration::from_millis(config.throttle_interval_ms),
        )
        .map_err(|_| Error::Invalid)?;
        let throttle = cthl::Throttle::new(
            "community",
            ACTIONS.iter().map(|a| (a.name, limit)),
            cthl::MemoryStore::new(NonZeroUsize::new(ACTIONS.len()).ok_or(Error::Invalid)?),
        )
        .map_err(|_| Error::Invalid)?;
        Ok(Self {
            inner: Arc::new(Inner {
                requests: Arc::new(Mutex::new(())),
                public_slots: Arc::new(Semaphore::new(32)),
                protected_slots: Arc::new(Semaphore::new(32)),
                watch_slots: Arc::new(Semaphore::new(16)),
                published,
                scope: Scope::Community,
                hosts,
                backend: Backend::Community(Box::new(Mutex::new(community))),
                member_host: Some(member_host),
                throttle,
                clock,
            }),
        })
    }
    pub(crate) fn allows_origin(&self, host: &str, origin: &str) -> bool {
        (self.inner.hosts.contains_key(host) || self.inner.member_host.as_deref() == Some(host))
            && (origin == format!("https://{host}")
                || (self.inner.member_host.as_deref() == Some(host)
                    && host
                        .strip_prefix("api.")
                        .is_some_and(|canonical| origin == format!("https://{canonical}"))))
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
            .allow_methods([Method::POST])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(Duration::from_secs(600))
    }
    fn auth(&self, host: &str) -> Result<Arc<Mutex<Auth>>> {
        self.inner.hosts.get(host).cloned().ok_or(Error::WrongHost)
    }
    pub(crate) async fn complete_context(
        &self,
        action: &Action,
        mut ctx: Context,
    ) -> Result<Context> {
        ctx.now = self.inner.clock.now();
        // Body receipt and queue waits cannot preserve a logged-out, expired or
        // revoked grant. Recheck the exact credential at execution time.
        if !matches!(
            action.name,
            "global_public" | "trust_feed" | "trust_changes"
        ) && let Some(token) = &ctx.token
        {
            if self.inner.member_host.as_deref() == Some(ctx.host.as_str()) {
                let (grant, authentication) = self
                    .community_backend()?
                    .lock()
                    .await
                    .authenticate(token, ctx.now)
                    .await?;
                ctx.grant = Some(grant);
                ctx.authentication = Some(authentication);
            } else {
                ctx.grant = Some(
                    self.auth(&ctx.host)?
                        .lock()
                        .await
                        .authenticate(token, ctx.now)
                        .await?,
                );
            }
        }
        Ok(ctx)
    }
    pub(crate) async fn admit_request(&self, action: &Action) -> Result<OwnedSemaphorePermit> {
        // Service-wide quotas cannot be evaded with forged IPs, handles or fresh tokens.
        if !matches!(
            self.inner.throttle.check(b"aggregate", action.name).await,
            Ok(cthl::Decision::Allowed)
        ) {
            return Err(Error::Throttled);
        }
        let slots = if action.name == "trust_changes" {
            &self.inner.watch_slots
        } else if action.access == Access::Public {
            &self.inner.public_slots
        } else {
            &self.inner.protected_slots
        };
        slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Throttled)
    }
    pub(crate) async fn authorize(&self, action: &Action, headers: &HeaderMap) -> Result<Context> {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::WrongHost)?
            .to_owned();
        let community_member = self.inner.member_host.as_deref() == Some(host.as_str());
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
        // Public metadata is independent of member credentials and activity.
        let token = if matches!(
            action.name,
            "global_public" | "trust_feed" | "trust_changes"
        ) {
            None
        } else {
            token
        };
        let (grant, authentication) = if let Some(token) = &token {
            if community_member {
                let (grant, authentication) = self
                    .community_backend()?
                    .lock()
                    .await
                    .authenticate(token, now)
                    .await?;
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
        if action.access != Access::Public {
            let grant = grant.as_ref().ok_or(Error::Unauthorized)?;
            let allowed = match action.access {
                Access::Authenticated => true,
                Access::Member => grant.role == Role::Member,
                Access::Admin => grant.role == Role::Admin,
                Access::Root => grant.role == Role::Root,
                Access::Public => true,
            };
            if !allowed {
                return Err(Error::Forbidden);
            }
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
    ) -> Result<User> {
        if self.inner.member_host.as_deref() == Some(ctx.host.as_str()) {
            return self
                .community_backend()?
                .lock()
                .await
                .register_finish(request, ctx.now)
                .await;
        }
        self.auth(&ctx.host)?
            .lock()
            .await
            .register_finish(request, ctx.now)
            .await
    }
    pub(crate) async fn login_begin(&self, ctx: Context, request: LoginStart) -> Result<Ceremony> {
        if self.inner.member_host.as_deref() == Some(ctx.host.as_str()) {
            return self
                .community_backend()?
                .lock()
                .await
                .login_begin(request, ctx.now)
                .await;
        }
        self.auth(&ctx.host)?
            .lock()
            .await
            .login_begin(request, ctx.now)
            .await
    }
    pub(crate) async fn login_finish(&self, ctx: Context, request: LoginFinish) -> Result<Session> {
        if self.inner.member_host.as_deref() == Some(ctx.host.as_str()) {
            return self
                .community_backend()?
                .lock()
                .await
                .login_finish(request, ctx.now)
                .await;
        }
        self.auth(&ctx.host)?
            .lock()
            .await
            .login_finish(request, ctx.now)
            .await
    }
    pub(crate) async fn logout(&self, ctx: Context, _: Empty) -> Result<Empty> {
        if self.inner.member_host.as_deref() == Some(ctx.host.as_str()) {
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
            .map_err(|_| Error::Refused)?;
        Ok(Bytes {
            bytes: challenge.to_bytes().to_vec(),
        })
    }
    pub(crate) async fn passport_issue(
        &self,
        ctx: Context,
        request: PassportIssue,
    ) -> Result<Bytes> {
        let challenge = cpsd::IssuanceChallenge::from_bytes(
            request.challenge.try_into().map_err(|_| Error::Invalid)?,
        );
        let request =
            cpsd::IssuanceRequest::from_bytes(&request.request).map_err(|_| Error::Invalid)?;
        let global = self.global_backend()?.lock().await;
        let passport = global
            .facade
            .issue(
                &mut cpsd::rand::rngs::OsRng,
                &ctx.global_session()?,
                &challenge,
                &request,
                ctx.now,
            )
            .await
            .map_err(|_| Error::Refused)?;
        Ok(Bytes {
            bytes: passport.to_bytes(),
        })
    }
    #[cfg(feature = "development-gate")]
    pub(crate) async fn development_gate(&self, ctx: Context, _: Empty) -> Result<Empty> {
        let global = self.global_backend()?.lock().await;
        let subject = ctx.subject()?;
        let check = cglb::CheckId::generate(&mut cpsd::rand::rngs::OsRng);
        global
            .facade
            .run_gate(
                &cglb::development::DevelopmentGate::new(global.development_expiry),
                &subject,
                subject.as_str().as_bytes(),
                ctx.now,
                &check,
            )
            .await
            .map_err(|_| Error::Refused)?;
        Ok(Empty {})
    }
    pub(crate) async fn global_warn(&self, _: Context, request: User) -> Result<Empty> {
        self.global_backend()?
            .lock()
            .await
            .facade
            .warn(&cglb::Subject::new(request.user).map_err(|_| Error::Invalid)?)
            .await
            .map_err(|_| Error::Refused)?;
        Ok(Empty {})
    }
    pub(crate) async fn global_suspend(&self, ctx: Context, request: Suspend) -> Result<Empty> {
        let mut global = self.global_backend()?.lock().await;
        global
            .facade
            .suspend(
                &cglb::Subject::new(request.user).map_err(|_| Error::Invalid)?,
                cglb::Suspension::Temporary {
                    until: request.until,
                },
                ctx.now,
            )
            .await
            .map_err(|_| Error::Refused)?;
        global.refresh(ctx.now).await?;
        Ok(Empty {})
    }
}

#[cfg(all(test, feature = "development-gate"))]
#[path = "service_tests.rs"]
mod tests;
