//! Community composition. No global identity, key or database capability enters it.
use crate::{
    api::*,
    auth::{Grant, token},
    config::{CommunityConfig, Config},
    error::{Error, Result},
    service::Clock,
};
use cmty::cplc::crbk;
use cmty::{cgts, cmbr, cplc};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

mod accounting;
mod certificate;
mod enrollment;
mod legal;
mod payments;
mod self_ban;
mod self_ban_status;
use legal::CommunityAuthority;
use payments::PaymentClock;
#[derive(Clone)]
pub struct CommunityClock(pub Arc<dyn Clock>);
impl clbs::Clock for CommunityClock {
    fn now(&self) -> clbs::Result<i64> {
        crate::service::operation_time(self.0.as_ref())
            .try_into()
            .map_err(|_| clbs::Error::Denied)
    }
}
type Rules = cmty::adapters::SharedRulebook<crbk::LibsqlStore>;
pub type Facade = cmty::Community<
    cmty::storage::LibsqlStorage,
    cmbr::LibsqlStorage,
    CommunityAuthority,
    CommunityClock,
    cgts::LibsqlStore,
    cgts::LegalGate<cgts::legal_storage::LibsqlStore, CommunityAuthority>,
    Rules,
    cplc::LibsqlStore,
    csgn::LibsqlStore,
>;
mod devices;

#[cfg(all(test, feature = "development-gate"))]
#[path = "community/tests/negative.rs"]
mod negative;
#[cfg(all(test, feature = "development-gate"))]
#[path = "community/tests/publication.rs"]
mod publication_tests;

struct Pending<T> {
    value: T,
    user: ckyh::Uuid,
    until: u64,
}
struct PendingLogin {
    value: cmbr::PendingLogin,
    until: u64,
}
struct Challenge {
    value: cmty::Challenge,
    owner: Option<ckyh::Uuid>,
    until: u64,
}
struct SessionState {
    authentication: Arc<ckyh::Authentication>,
    grant: Grant,
}
pub struct CommunityService {
    pub facade: Facade,
    db: crlt::Db,
    issuer_public_key: Vec<u8>,
    pub config: CommunityConfig,
    pub public: TrustFeed,
    pub changes: tokio::sync::watch::Sender<Arc<TrustFeed>>,
    voucher: cgts::gates::VoucherGate,
    pub payments: Option<Arc<tokio::sync::Mutex<crate::payments::PaymentHost>>>,
    accounts: Option<Arc<crate::accounting::clock::AccountRuntime>>,
    challenges: HashMap<String, Challenge>,
    registrations: HashMap<String, Pending<cmbr::PendingRegistration>>,
    logins: HashMap<String, PendingLogin>,
    additions: HashMap<String, devices::PendingAddition>,
    self_bans: HashMap<String, self_ban::PendingSelfBan>,
    self_ban_statuses: HashMap<String, self_ban_status::PendingStatus>,
    authority: CommunityAuthority,
    clock: Arc<dyn Clock>,
    sessions: HashMap<String, SessionState>,
}
impl CommunityService {
    pub async fn open(
        db: &crlt::Db,
        config: CommunityConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        Self::open_with_payment_transport(db, config, clock, None).await
    }
    pub async fn open_with_payment_transport(
        db: &crlt::Db,
        config: CommunityConfig,
        clock: Arc<dyn Clock>,
        transport: Option<crate::payments::transport::AnyTransport>,
    ) -> Result<Self> {
        use cplc::Storage;
        use csgn::Store;
        let now = clock.now();
        if config.community.is_empty()
            || config.community.len() > 63
            || !config
                .community
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || ["root", "admin", "api", "www", "mail", "mcp", "wallet"]
                .contains(&config.community.as_str())
            || config.pending_capacity == 0
            || config.session_seconds == 0
            || config.session_seconds > 3600
            || config.lease_months == 0
        {
            return Err(Error::Invalid);
        }
        let migrations = crate::service::community_migrations();
        db.migrate(&migrations)
            .await
            .map_err(Error::Unavailable.redact())?;
        crate::identity::bind(db, "community", &config.community).await?;
        let global = crate::global_trust::load(db, &config, now).await?;
        let status = global.status;
        let status_until = global.valid_until;
        let scope = &config.community;
        let signer_store =
            csgn::LibsqlStore::new(db.community(scope).map_err(Error::Invalid.redact())?);
        let saved = signer_store
            .load(scope)
            .await
            .map_err(Error::Unavailable.redact())?;
        let secret = csgn::SecretKey::from_seed(&mut Config::seed(&config.signing_seed_file)?);
        if global.signing_keys.contains(&secret.public_key())
            || saved.as_ref().is_some_and(|saved| {
                saved
                    .state
                    .key_ring()
                    .keys()
                    .iter()
                    .any(|key| global.signing_keys.contains(&key.public_key()))
            })
        {
            return Err(Error::Invalid);
        }
        let signer = if saved.is_some() {
            // cplc signs at UTC-day precision; recovery must use the same clock domain.
            csgn::PersistentSigner::open(signer_store, scope, secret, cplc::day(now)).await
        } else {
            csgn::PersistentSigner::create(
                signer_store,
                scope,
                secret,
                cplc::day(now),
                config.signer_max_seconds,
            )
            .await
        }
        .map_err(Error::Unavailable.redact())?;
        let rules = Rules::new(crbk::LibsqlStore::new(db.clone()));
        let policy_store =
            cplc::LibsqlStore::new(db, scope).map_err(Error::Unavailable.redact())?;
        let exists = policy_store
            .load()
            .await
            .map_err(Error::Unavailable.redact())?
            .is_some();
        let mut policy = if exists {
            cplc::Policy::open(rules.clone(), policy_store, signer).await
        } else {
            cplc::Policy::create(
                rules.clone(),
                policy_store,
                signer,
                cplc::Config {
                    credential_action: cmty::ADMISSION_ACTION.into(),
                    snapshot_validity: config.publication_seconds,
                },
            )
            .await
        }
        .map_err(Error::Unavailable.redact())?;
        if !exists {
            let rulebook = serde_json::from_slice(
                &std::fs::read(&config.rulebook_file).map_err(Error::Unavailable.redact())?,
            )
            .map_err(Error::Invalid.redact())?;
            policy
                .schedule_rules(
                    None,
                    crbk::Change {
                        rulebook,
                        announced_at: now as i64,
                        effective_at: now as i64,
                        notice_seconds: 0,
                        policy_epoch: 1,
                    },
                )
                .await
                .map_err(Error::Refused.redact())?;
            let schema = serde_json::from_slice(
                &std::fs::read(&config.schema_file).map_err(Error::Unavailable.redact())?,
            )
            .map_err(Error::Invalid.redact())?;
            policy
                .set_schema(schema)
                .await
                .map_err(Error::Refused.redact())?;
            policy
                .set_communities(BTreeSet::from([scope.clone()]))
                .await
                .map_err(Error::Refused.redact())?;
        }
        let account_parts = if let Some(account) = config.accounting.clone() {
            let ring = policy
                .key_ring()
                .map_err(Error::Unavailable.redact())?
                .clone();
            let account_db = db.clone();
            let account_community = config.community.clone();
            let account_clock = clock.clone();
            let runtime = tokio::runtime::Handle::current();
            // Native proof verification and every synchronous CRLT call remain
            // off the async executor. The original CGTS worker then owns/drops
            // this ONE service; no second ledger or database is created.
            let (service, observed) = tokio::task::spawn_blocking(move || {
                account.build(
                    &account_db,
                    &account_community,
                    ring,
                    account_clock,
                    runtime,
                )
            })
            .await
            .map_err(Error::Unavailable.redact())??;
            Some((service, observed))
        } else {
            None
        };
        let owner_clock: Arc<dyn Clock> = match &account_parts {
            Some((_, observed)) => observed.clone(),
            None => clock.clone(),
        };
        // Entry, legal/lifecycle checks, payments and final publication share
        // the native owner's greatest observation when accounts are installed.
        let clock = owner_clock.clone();
        let host = format!("api.{}.{}", scope, config.domain);
        let authority =
            CommunityAuthority::new(scope, owner_clock.clone(), config.pending_capacity)?;
        let membership = cmbr::Membership::new(
            db,
            cmbr::LibsqlStorage::new(db, scope).map_err(Error::Unavailable.redact())?,
            cmbr::Config {
                pending_days: config.pending_days,
                membership_action: cmty::ADMISSION_ACTION.into(),
                release_period: Default::default(),
                lease_months: config.lease_months,
                rp_id: format!("{scope}.{}", config.domain),
                origins: vec![
                    ckyh::Url::parse(&format!("https://{host}"))
                        .map_err(Error::Invalid.redact())?,
                    ckyh::Url::parse(&format!("https://{scope}.{}", config.domain))
                        .map_err(Error::Invalid.redact())?,
                    ckyh::Url::parse(&format!("https://vault.{scope}.{}", config.domain))
                        .map_err(Error::Invalid.redact())?,
                ],
            },
            authority.clone(),
            CommunityClock(owner_clock),
        )
        .map_err(Error::Invalid.redact())?;
        // One process owns this database. cmbr serializes member operations;
        // the door serializes the complete gate/policy/membership composition.
        let gates = cgts::Gatekeeper::new(
            cgts::LibsqlStore::new(db, scope).map_err(Error::Unavailable.redact())?,
            cgts::LegalGate::new(
                cgts::legal_storage::LibsqlStore::new(db, scope)
                    .map_err(Error::Unavailable.redact())?,
                authority.clone(),
            ),
        )
        .map_err(Error::Invalid.redact())?;
        let mut facade = cmty::Community::new(
            cmty::storage::LibsqlStorage::new(
                db,
                cpsd::CommunityId::new(scope.as_bytes()).map_err(Error::Invalid.redact())?,
                config.pending_capacity,
            )
            .map_err(Error::Unavailable.redact())?,
            vec![
                cpsd::IssuerPublicKey::from_bytes(&status.issuer_public_key)
                    .map_err(Error::Invalid.redact())?,
            ],
            cmty::Parts {
                membership,
                gates,
                policy,
            },
            cmty::Config {
                passport: cmty::PassportPolicy {
                    epoch: status.epoch,
                    valid_until: status.shared_expiry,
                    gates: config
                        .global_gates
                        .iter()
                        .map(|s| cpsd::GateId::new(s.clone()))
                        .collect::<std::result::Result<_, _>>()
                        .map_err(Error::Invalid.redact())?,
                },
                valid_until: status_until,
                challenge_lifetime: 60,
            },
        )
        .map_err(Error::Invalid.redact())?;
        let accounts = if let Some((service, observed)) = account_parts {
            facade = facade
                .with_native_account_service(service)
                .await
                .map_err(Error::Unavailable.redact())?;
            Some(observed)
        } else {
            None
        };
        // Capture the actual join owner BEFORE bootstrap or any later fallible
        // wait. Returned errors await completion; abandoned futures start it.
        let shutdown = if accounts.is_some() {
            Some(
                facade
                    .account_shutdown()
                    .map_err(Error::Unavailable.redact())?,
            )
        } else {
            None
        };
        let startup = crate::accounting::startup::Startup::new(accounts.clone(), shutdown);
        let scope = config.community.clone();
        let result = async {
            if let Some(observed) = &accounts {
                let publisher_clock = observed.clone();
                facade
                    .publish_account_material(&observed.period_key, move || {
                        publisher_clock.native_time()
                    })
                    .await
                    .map_err(Error::Unavailable.redact())?;
            }
            let key: [u8; 32] = std::fs::read(&config.voucher_public_key_file)
                .map_err(Error::Unavailable.redact())?
                .try_into()
                .map_err(Error::Invalid.redact())?;
            let voucher = cgts::gates::VoucherGate::new(
                config.voucher_provider.clone(),
                ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(Error::Invalid.redact())?,
            )
            .map_err(Error::Invalid.redact())?;
            let public_now = accounts
                .as_ref()
                .map_or(Ok(now), |observed| observed.observe())?;
            let public = publish(&facade, public_now).await?;
            let payments = match config.payments.clone() {
                Some(payment) => Some(Arc::new(tokio::sync::Mutex::new(
                    crate::payments::PaymentHost::open(
                        db,
                        payment,
                        scope.clone(),
                        cmty::ADMISSION_ACTION.into(),
                        Arc::new(PaymentClock(clock.clone())),
                        transport,
                    )
                    .await
                    .map_err(Error::Invalid.redact())?,
                ))),
                None if transport.is_some() => return Err(Error::Invalid),
                None => None,
            };
            let (changes, _) = tokio::sync::watch::channel(Arc::new(public.clone()));
            // A configured facade must not escape a startup wait below an interior
            // native/host observation. Keep every already signed deadline unchanged.
            if let Some(observed) = &accounts {
                observed.observe()?;
            }
            Ok(Self {
                facade,
                db: db.clone(),
                issuer_public_key: status.issuer_public_key,
                config,
                public,
                changes,
                voucher,
                payments,
                accounts,
                challenges: HashMap::new(),
                registrations: HashMap::new(),
                logins: HashMap::new(),
                additions: HashMap::new(),
                self_bans: HashMap::new(),
                self_ban_statuses: HashMap::new(),
                authority,
                clock,
                sessions: HashMap::new(),
            })
        }
        .await;
        startup.finish(result).await
    }
    async fn refresh_global(&self, now: u64) -> Result<()> {
        let global = crate::global_trust::load(&self.db, &self.config, now).await?;
        crate::service::publication::expires_at(global.valid_until)?;
        let policy = self.facade.policy().lock().await;
        if policy
            .key_ring()
            .map_err(Error::Unavailable.redact())?
            .keys()
            .iter()
            .any(|key| global.signing_keys.contains(&key.public_key()))
        {
            return Err(Error::Invalid);
        }
        drop(policy);
        if global.status.issuer_public_key != self.issuer_public_key {
            return Err(Error::Refused);
        }
        self.facade
            .refresh_passport_policy(
                cmty::PassportPolicy {
                    epoch: global.status.epoch,
                    valid_until: global.status.shared_expiry,
                    gates: self
                        .config
                        .global_gates
                        .iter()
                        .map(|gate| cpsd::GateId::new(gate.clone()))
                        .collect::<std::result::Result<_, _>>()
                        .map_err(Error::Invalid.redact())?,
                },
                global.valid_until,
                now,
            )
            .await
            .map_err(Error::Refused.redact())
    }
    fn prune(&mut self, now: u64) {
        self.challenges.retain(|_, p| p.until > now);
        self.registrations.retain(|_, p| p.until > now);
        self.logins.retain(|_, p| p.until > now);
        self.additions.retain(|_, p| p.until > now);
        self.self_bans.retain(|_, p| p.until > now);
        self.self_ban_statuses.retain(|_, p| p.until > now);
        self.sessions.retain(|_, s| s.grant.expires > now);
    }
    pub async fn authenticate(
        &mut self,
        token: &str,
        now: u64,
    ) -> Result<(Grant, Arc<ckyh::Authentication>)> {
        self.prune(now);
        self.authenticate_current(token, now).await
    }
    async fn authenticate_current(
        &self,
        token: &str,
        now: u64,
    ) -> Result<(Grant, Arc<ckyh::Authentication>)> {
        let session = self
            .sessions
            .get(token)
            .filter(|session| now < session.grant.expires)
            .ok_or(Error::Unauthorized)?;
        if !self
            .facade
            .membership()
            .session_is_active(&session.authentication, &session.grant.credential)
            .await
            .map_err(Error::Unauthorized.redact())?
        {
            return Err(Error::Unauthorized);
        }
        Ok((session.grant.clone(), session.authentication.clone()))
    }
    pub async fn challenge(
        &mut self,
        owner: Option<ckyh::Uuid>,
        now: u64,
    ) -> Result<PresentationChallenge> {
        self.refresh_global(now).await?;
        self.prune(now);
        if self.challenges.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        let challenge = self
            .facade
            .begin(&mut cpsd::rand::rngs::OsRng, now)
            .await
            .map_err(Error::Refused.redact())?;
        let request = challenge.signed_request().to_vec();
        let id = token();
        crate::service::publication::expires_at(now + 60)?;
        self.challenges.insert(
            id.clone(),
            Challenge {
                value: challenge,
                owner,
                until: now + 60,
            },
        );
        Ok(PresentationChallenge {
            challenge: id,
            request,
        })
    }
    pub async fn register_begin(&mut self, request: RegisterStart, now: u64) -> Result<Ceremony> {
        self.register_begin_for(request, None, now).await
    }
    async fn register_begin_for(
        &mut self,
        request: RegisterStart,
        seed: Option<[u8; 32]>,
        now: u64,
    ) -> Result<Ceremony> {
        self.refresh_global(now).await?;
        self.prune(now);
        if self.registrations.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        if request.bootstrap.is_some() {
            return Err(Error::Forbidden);
        }
        let input = request.passport.ok_or(Error::Invalid)?;
        let challenge = self
            .challenges
            .remove(&input.challenge)
            .ok_or(Error::Refused)?;
        crate::service::publication::expires_at(challenge.until)?;
        if challenge.owner.is_some() {
            return Err(Error::Forbidden);
        }
        let proof =
            cpsd::Presentation::from_bytes(&input.proof).map_err(Error::Invalid.redact())?;
        let passport = self
            .facade
            .verify(&mut cpsd::rand::rngs::OsRng, &challenge.value, &proof, now)
            .await
            .map_err(Error::Refused.redact())?;
        let user = ckyh::Uuid::new_v4();
        let (options, value) = match seed {
            Some(seed) => {
                self.facade
                    .begin_initial_registration(passport, user, seed, now)
                    .await
            }
            None => self.facade.begin_registration(passport, user, now).await,
        }
        .map_err(Error::Refused.redact())?;
        let id = token();
        crate::service::publication::expires_at(now + 300)?;
        self.registrations.insert(
            id.clone(),
            Pending {
                value,
                user,
                until: now + 300,
            },
        );
        Ok(Ceremony {
            ceremony: id,
            user: user.to_string(),
            options: serde_json::to_value(options).map_err(Error::Unavailable.redact())?,
        })
    }
    pub async fn register_finish(&mut self, request: RegisterFinish, now: u64) -> Result<User> {
        self.prune(now);
        let pending = self
            .registrations
            .remove(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        crate::service::publication::expires_at(pending.until)?;
        self.facade
            .membership()
            .finish_registration(pending.value, request.credential)
            .await
            .map_err(Error::Refused.redact())?;
        Ok(User {
            user: pending.user.to_string(),
        })
    }
    pub async fn login_begin(&mut self, request: LoginStart, now: u64) -> Result<Ceremony> {
        self.prune(now);
        if self.logins.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        let user = ckyh::Uuid::parse_str(&request.user).map_err(Error::Invalid.redact())?;
        let (options, value) = self
            .facade
            .membership()
            .begin_login(user, request.credential.into())
            .await
            .map_err(Error::Unauthorized.redact())?;
        let id = token();
        crate::service::publication::expires_at(now + 300)?;
        self.logins.insert(
            id.clone(),
            PendingLogin {
                value,
                until: now + 300,
            },
        );
        Ok(Ceremony {
            ceremony: id,
            user: user.to_string(),
            options: serde_json::to_value(options).map_err(Error::Unavailable.redact())?,
        })
    }
    pub async fn login_discoverable_begin(&mut self, now: u64) -> Result<DiscoverableCeremony> {
        self.prune(now);
        if self.logins.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        let (options, value) = self
            .facade
            .membership()
            .begin_discoverable_login()
            .await
            .map_err(Error::Unauthorized.redact())?;
        let id = token();
        crate::service::publication::expires_at(now + 300)?;
        self.logins.insert(
            id.clone(),
            PendingLogin {
                value,
                until: now + 300,
            },
        );
        Ok(DiscoverableCeremony {
            ceremony: id,
            options: serde_json::to_value(options).map_err(Error::Unavailable.redact())?,
        })
    }
    pub async fn login_finish(&mut self, request: LoginFinish, now: u64) -> Result<Session> {
        self.prune(now);
        if self.sessions.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        let pending = self
            .logins
            .remove(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        crate::service::publication::expires_at(pending.until)?;
        let credential = request.credential.raw_id.clone().into();
        let login = self
            .facade
            .membership()
            .finish_login(pending.value, request.credential)
            .await
            .map_err(Error::Unauthorized.redact())?;
        let user = login.authentication.member();
        let expires = now + self.config.session_seconds;
        crate::service::publication::expires_at(expires)?;
        let id = token();
        self.sessions.insert(
            id.clone(),
            SessionState {
                authentication: Arc::new(login.authentication),
                grant: Grant {
                    user,
                    role: Role::Member,
                    expires,
                    credential,
                    session_id: rand::random(),
                },
            },
        );
        Ok(Session {
            token: id,
            user: user.to_string(),
            role: Role::Member,
            expires,
        })
    }
    pub fn logout(&mut self, token: &str) {
        if let Some(session) = self.sessions.remove(token) {
            self.additions
                .retain(|_, p| p.session_id != session.grant.session_id);
            self.self_bans
                .retain(|_, p| p.session_id != session.grant.session_id);
        }
    }
    pub async fn reserved(&self, now: u64) -> Result<Vec<String>> {
        let policy = self
            .facade
            .policy()
            .lock()
            .await
            .settings(now)
            .await
            .map_err(Error::Refused.redact())?;
        serde_json::from_value(
            policy
                .content
                .get("handles.reserved")
                .cloned()
                .ok_or(Error::Unavailable)?,
        )
        .map_err(Error::Unavailable.redact())
    }
    pub async fn lobby(&self, auth: &ckyh::Authentication, now: u64) -> Result<Lobby> {
        use cgts::Gate;
        let policy = self.facade.policy().lock().await;
        let settings = policy
            .published(cplc::SnapshotKind::Settings, now)
            .await
            .map_err(Error::Unavailable.redact())?
            .ok_or(Error::Unavailable)?;
        let snapshot = cplc::verify_settings(
            policy.key_ring().map_err(Error::Unavailable.redact())?,
            &settings,
            cplc::SnapshotExpectation {
                community: &self.config.community,
                kind: cplc::SnapshotKind::Settings,
                minimum_revision: 1,
                policy_epoch: policy
                    .epoch(now)
                    .await
                    .map_err(Error::Unavailable.redact())?,
                now,
            },
        )
        .map_err(Error::Unavailable.redact())?;
        let row = self
            .facade
            .membership()
            .resume(auth)
            .await
            .map_err(Error::Refused.redact())?;
        let context = cgts::Context {
            snapshot: snapshot.settings(),
            subject: row.subject(),
            action: cmty::ADMISSION_ACTION,
            now: now as i64,
        };
        // No cached global assertion: a credential always requires a fresh passport.
        let gates = self
            .facade
            .gates()
            .check(context, Vec::new())
            .await
            .map_err(Error::Refused.redact())?;
        let lobby = self
            .facade
            .membership()
            .lobby(auth, &*policy, &snapshot, &gates)
            .await
            .map_err(Error::Refused.redact())?;
        let steps = self
            .facade
            .gates()
            .steps(context, &[self.voucher.descriptor()])
            .await
            .map_err(Error::Refused.redact())?;
        let handle = self
            .facade
            .membership()
            .handle(auth)
            .await
            .map_err(Error::Refused.redact())?
            .map(|h| h.display().to_owned());
        Ok(Lobby {
            member_id: lobby.enrolment.subject().into(),
            state: serde_json::to_value(lobby.enrolment.state())
                .map_err(Error::Unavailable.redact())?
                .as_str()
                .ok_or(Error::Unavailable)?
                .into(),
            handle,
            missing: serde_json::to_value(lobby.decision.missing)
                .map_err(Error::Unavailable.redact())?,
            steps: steps
                .into_iter()
                .map(|s| serde_json::to_value(s).expect("serializable step"))
                .collect(),
            warnings: lobby
                .warnings
                .into_iter()
                .map(|warning| match warning {
                    cmbr::Warning::RegistrationExpires { deadline } => {
                        LobbyWarning::RegistrationExpires { deadline }
                    }
                    cmbr::Warning::AddSecondDeviceOrSyncedPasskey => {
                        LobbyWarning::AddSecondDeviceOrSyncedPasskey
                    }
                })
                .collect(),
            passport_required: true,
        })
    }
    pub async fn voucher(
        &self,
        auth: &ckyh::Authentication,
        request: Voucher,
        now: u64,
    ) -> Result<()> {
        let row = self
            .facade
            .membership()
            .resume(auth)
            .await
            .map_err(Error::Refused.redact())?;
        let policy = self
            .facade
            .snapshot(now)
            .await
            .map_err(Error::Refused.redact())?;
        let input: <cgts::gates::VoucherGate as cgts::Gate>::Input =
            serde_json::from_value(serde_json::to_value(request).map_err(Error::Invalid.redact())?)
                .map_err(Error::Invalid.redact())?;
        self.facade
            .gates()
            .run(
                cgts::Context {
                    snapshot: &policy.rules,
                    subject: row.subject(),
                    action: cmty::ADMISSION_ACTION,
                    now: now as i64,
                },
                &self.voucher,
                &input,
            )
            .await
            .map_err(Error::Refused.redact())?;
        Ok(())
    }
    pub async fn issue(
        &mut self,
        auth: &ckyh::Authentication,
        request: CredentialRequest,
        withdrawal: Option<(String, String)>,
        now: u64,
    ) -> Result<CredentialResponse> {
        self.issue_selected(auth, request, withdrawal, None, now)
            .await
            .map(|(response, _)| response)
    }
    async fn issue_selected(
        &mut self,
        auth: &ckyh::Authentication,
        request: CredentialRequest,
        withdrawal: Option<(String, String)>,
        account_device: Option<[u8; 32]>,
        now: u64,
    ) -> Result<(CredentialResponse, Option<cblc::admission::AdmissionGrant>)> {
        use chrono::Datelike;
        self.refresh_global(now).await?;
        self.prune(now);
        let challenge = self
            .challenges
            .remove(&request.presentation.challenge)
            .ok_or(Error::Refused)?;
        crate::service::publication::expires_at(challenge.until)?;
        if challenge.owner != Some(auth.member()) {
            return Err(Error::Forbidden);
        }
        let proof = cpsd::Presentation::from_bytes(&request.presentation.proof)
            .map_err(Error::Invalid.redact())?;
        let date = chrono::DateTime::from_timestamp(now as i64, 0)
            .ok_or(Error::Invalid)?
            .checked_add_months(chrono::Months::new(self.config.lease_months))
            .ok_or(Error::Invalid)?;
        let lease = cmbr::YearMonth::new(date.year() as u16, date.month() as u8)
            .map_err(Error::Invalid.redact())?;
        let admission = cmty::Admission {
            authentication: auth,
            devices: &request.devices,
            lease,
        };
        let checks = async |gates: &cgts::Gatekeeper<_, _>, context: cgts::Context<'_>| {
            if let Some((gate, provider)) = withdrawal {
                gates.withdraw(context.subject, &gate, &provider).await?;
            }
            Ok(Vec::new())
        };
        let result = match account_device {
            Some(device) => {
                self.facade
                    .finish_account_with(
                        &mut cpsd::rand::rngs::OsRng,
                        &challenge.value,
                        &proof,
                        cmty::AccountAdmission {
                            membership: admission,
                            device,
                        },
                        now,
                        checks,
                    )
                    .await
            }
            None => {
                self.facade
                    .finish_with(
                        &mut cpsd::rand::rngs::OsRng,
                        &challenge.value,
                        &proof,
                        admission,
                        now,
                        checks,
                    )
                    .await
            }
        }
        .map_err(|error| {
            if account_device.is_some() && error == cmty::Error::Reconcile {
                Error::Reconcile
            } else {
                Error::Refused
            }
        })?;
        let (credential, account) = match result {
            cmty::Outcome::Issued(value) => (Some(value.cose), value.account),
            cmty::Outcome::Missing(_) => (None, None),
            cmty::Outcome::Vetoed => return Err(Error::Forbidden),
        };
        let completed = async {
            if self
                .facade
                .flush_revocations(now)
                .await
                .map_err(Error::Unavailable.redact())?
                > 0
            {
                self.refresh(now).await?;
            }
            let lobby = self.lobby(auth, now).await?;
            Ok((CredentialResponse { credential, lobby }, account))
        }
        .await;
        // The selected account admission may already be durable. A later
        // publication/lobby failure withholds its result without a rollback claim.
        completed.map_err(|error| {
            if account_device.is_some() {
                Error::Reconcile
            } else {
                error
            }
        })
    }
    pub async fn refresh(&mut self, now: u64) -> Result<()> {
        self.public = publish(&self.facade, now).await?;
        self.changes.send_replace(Arc::new(self.public.clone()));
        Ok(())
    }
    pub async fn maintain(&mut self, now: u64) -> Result<()> {
        // Stale global metadata blocks admission, but cannot stop local cleanup.
        let _ = self.refresh_global(now).await;
        self.prune(now);
        self.facade
            .prune(now)
            .await
            .map_err(Error::Unavailable.redact())?;
        self.facade
            .membership()
            .maintain(100)
            .await
            .map_err(Error::Unavailable.redact())?;
        self.facade
            .flush_revocations(now)
            .await
            .map_err(Error::Unavailable.redact())?;
        let policy = self.facade.policy().lock().await;
        let epoch = policy
            .epoch(now)
            .await
            .map_err(Error::Unavailable.redact())?;
        let fresh = policy
            .key_ring()
            .map_err(Error::Unavailable.redact())?
            .verify(&self.public.manifest, csgn::Kind::SettingsSnapshot, now)
            .map(|s| s.valid_until() > now + self.config.publication_seconds / 2)
            .unwrap_or(false);
        drop(policy);
        if !fresh || epoch != self.public.policy_epoch {
            self.refresh(now).await?;
        }
        Ok(())
    }
}
async fn publish(facade: &Facade, now: u64) -> Result<TrustFeed> {
    let feed = facade
        .policy()
        .lock()
        .await
        .refresh_trust(now)
        .await
        .map_err(Error::Unavailable.redact())?;
    Ok(TrustFeed {
        revision: feed.revision,
        policy_epoch: feed.policy_epoch,
        key_ring: feed.key_ring.clone(),
        key_transitions: feed
            .key_transitions
            .iter()
            .map(|transition| TrustKeyTransition {
                revision: transition.revision,
                proof: transition.proof.clone(),
            })
            .collect(),
        manifest: feed.manifest.clone(),
        settings: feed.settings.clone(),
        schema: feed.schema.clone(),
        communities: feed.communities.clone(),
        revocations: feed.revocations.clone(),
        schema_versions: feed.schema_versions.clone(),
        root_board: feed.root_board.clone(),
        balance: feed.balance.clone(),
    })
}
