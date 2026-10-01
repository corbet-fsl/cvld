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

#[derive(Clone)]
pub struct UnconfiguredAuthority;
impl clbs::Verifier for UnconfiguredAuthority {
    async fn verify_legal(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
    async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
}
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
    UnconfiguredAuthority,
    CommunityClock,
    cgts::LibsqlStore,
    cgts::LegalGate<clbs::LibsqlStore, UnconfiguredAuthority>,
    Rules,
    cplc::LibsqlStore,
    csgn::LibsqlStore,
>;
mod devices;

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
    challenges: HashMap<String, Challenge>,
    registrations: HashMap<String, Pending<cmbr::PendingRegistration>>,
    logins: HashMap<String, PendingLogin>,
    additions: HashMap<String, devices::PendingAddition>,
    sessions: HashMap<String, SessionState>,
}
impl CommunityService {
    pub async fn open(
        db: &crlt::Db,
        config: CommunityConfig,
        clock: Arc<dyn Clock>,
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
        let mut schemas = cmbr::SCHEMAS.to_vec();
        schemas.extend([
            ("cgts", cgts::SCHEMA),
            ("crbk", crbk::SCHEMA),
            ("cplc", cplc::SCHEMA),
            ("csgn", csgn::SCHEMA),
            ("cpsd", cmty::storage::SCHEMA),
            ("service", crate::identity::SCHEMA),
            ("global-trust", crate::global_trust::SCHEMA),
            ("cmbr-device-keys", cmbr::DEVICE_KEYS_SCHEMA),
        ]);
        let migrations: Vec<_> = schemas
            .iter()
            .enumerate()
            .map(|(i, (name, sql))| crlt::Migration::new(i as u32 + 1, name, sql))
            .collect();
        db.migrate(&migrations)
            .await
            .map_err(|_| Error::Unavailable)?;
        crate::identity::bind(db, "community", &config.community).await?;
        let global = crate::global_trust::load(db, &config, now).await?;
        let status = global.status;
        let status_until = global.valid_until;
        let scope = &config.community;
        let signer_store = csgn::LibsqlStore::new(db.community(scope).map_err(|_| Error::Invalid)?);
        let saved = signer_store
            .load(scope)
            .await
            .map_err(|_| Error::Unavailable)?;
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
            csgn::PersistentSigner::open(signer_store, scope, secret, now).await
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
        .map_err(|_| Error::Unavailable)?;
        let rules = Rules::new(crbk::LibsqlStore::new(db.clone()));
        let policy_store = cplc::LibsqlStore::new(db, scope).map_err(|_| Error::Unavailable)?;
        let exists = policy_store
            .load()
            .await
            .map_err(|_| Error::Unavailable)?
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
        .map_err(|_| Error::Unavailable)?;
        if !exists {
            let rulebook = serde_json::from_slice(
                &std::fs::read(&config.rulebook_file).map_err(|_| Error::Unavailable)?,
            )
            .map_err(|_| Error::Invalid)?;
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
                .map_err(|_| Error::Refused)?;
            let schema = serde_json::from_slice(
                &std::fs::read(&config.schema_file).map_err(|_| Error::Unavailable)?,
            )
            .map_err(|_| Error::Invalid)?;
            policy
                .set_schema(schema)
                .await
                .map_err(|_| Error::Refused)?;
            policy
                .set_communities(BTreeSet::from([scope.clone()]))
                .await
                .map_err(|_| Error::Refused)?;
        }
        let host = format!("api.{}.{}", scope, config.domain);
        let membership = cmbr::Membership::new(
            db,
            cmbr::LibsqlStorage::new(db, scope).map_err(|_| Error::Unavailable)?,
            cmbr::Config {
                pending_days: config.pending_days,
                membership_action: cmty::ADMISSION_ACTION.into(),
                release_period: Default::default(),
                lease_months: config.lease_months,
                rp_id: format!("{scope}.{}", config.domain),
                origins: vec![
                    ckyh::Url::parse(&format!("https://{host}")).map_err(|_| Error::Invalid)?,
                    ckyh::Url::parse(&format!("https://{scope}.{}", config.domain))
                        .map_err(|_| Error::Invalid)?,
                    ckyh::Url::parse(&format!("https://vault.{scope}.{}", config.domain))
                        .map_err(|_| Error::Invalid)?,
                ],
            },
            UnconfiguredAuthority,
            CommunityClock(clock),
        )
        .map_err(|_| Error::Invalid)?;
        // One process owns this database. cmbr serializes member operations;
        // the door serializes the complete gate/policy/membership composition.
        let gates = cgts::Gatekeeper::new(
            cgts::LibsqlStore::new(db, scope).map_err(|_| Error::Unavailable)?,
            cgts::LegalGate::new(
                clbs::LibsqlStore::new(db, scope).map_err(|_| Error::Unavailable)?,
                UnconfiguredAuthority,
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let facade = cmty::Community::new(
            cmty::storage::LibsqlStorage::new(
                db,
                cpsd::CommunityId::new(scope.as_bytes()).map_err(|_| Error::Invalid)?,
                config.pending_capacity,
            )
            .map_err(|_| Error::Unavailable)?,
            vec![
                cpsd::IssuerPublicKey::from_bytes(&status.issuer_public_key)
                    .map_err(|_| Error::Invalid)?,
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
                        .map_err(|_| Error::Invalid)?,
                },
                valid_until: status_until,
                challenge_lifetime: 60,
            },
        )
        .map_err(|_| Error::Invalid)?;
        let key: [u8; 32] = std::fs::read(&config.voucher_public_key_file)
            .map_err(|_| Error::Unavailable)?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let voucher = cgts::gates::VoucherGate::new(
            config.voucher_provider.clone(),
            ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| Error::Invalid)?,
        )
        .map_err(|_| Error::Invalid)?;
        let public = publish(&facade, now).await?;
        let (changes, _) = tokio::sync::watch::channel(Arc::new(public.clone()));
        Ok(Self {
            facade,
            db: db.clone(),
            issuer_public_key: status.issuer_public_key,
            config,
            public,
            changes,
            voucher,
            challenges: HashMap::new(),
            registrations: HashMap::new(),
            logins: HashMap::new(),
            additions: HashMap::new(),
            sessions: HashMap::new(),
        })
    }
    async fn refresh_global(&self, now: u64) -> Result<()> {
        let global = crate::global_trust::load(&self.db, &self.config, now).await?;
        let policy = self.facade.policy().lock().await;
        if policy
            .key_ring()
            .map_err(|_| Error::Unavailable)?
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
                        .map_err(|_| Error::Invalid)?,
                },
                global.valid_until,
                now,
            )
            .await
            .map_err(|_| Error::Refused)
    }
    fn prune(&mut self, now: u64) {
        self.challenges.retain(|_, p| p.until > now);
        self.registrations.retain(|_, p| p.until > now);
        self.logins.retain(|_, p| p.until > now);
        self.additions.retain(|_, p| p.until > now);
        self.sessions.retain(|_, s| s.grant.expires > now);
    }
    pub async fn authenticate(
        &mut self,
        token: &str,
        now: u64,
    ) -> Result<(Grant, Arc<ckyh::Authentication>)> {
        self.prune(now);
        let session = self.sessions.get(token).ok_or(Error::Unauthorized)?;
        if !self
            .facade
            .membership()
            .session_is_active(&session.authentication, &session.grant.credential)
            .await
            .map_err(|_| Error::Unauthorized)?
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
            .map_err(|_| Error::Refused)?;
        let request = challenge.signed_request().to_vec();
        let id = token();
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
        if challenge.owner.is_some() {
            return Err(Error::Forbidden);
        }
        let proof = cpsd::Presentation::from_bytes(&input.proof).map_err(|_| Error::Invalid)?;
        let passport = self
            .facade
            .verify(&mut cpsd::rand::rngs::OsRng, &challenge.value, &proof, now)
            .await
            .map_err(|_| Error::Refused)?;
        let user = ckyh::Uuid::new_v4();
        let (options, value) = self
            .facade
            .begin_registration(passport, user, now)
            .await
            .map_err(|_| Error::Refused)?;
        let id = token();
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
            options: serde_json::to_value(options).map_err(|_| Error::Unavailable)?,
        })
    }
    pub async fn register_finish(&mut self, request: RegisterFinish, now: u64) -> Result<User> {
        self.prune(now);
        let pending = self
            .registrations
            .remove(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        self.facade
            .membership()
            .finish_registration(pending.value, request.credential)
            .await
            .map_err(|_| Error::Refused)?;
        Ok(User {
            user: pending.user.to_string(),
        })
    }
    pub async fn login_begin(&mut self, request: LoginStart, now: u64) -> Result<Ceremony> {
        self.prune(now);
        if self.logins.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        let user = ckyh::Uuid::parse_str(&request.user).map_err(|_| Error::Invalid)?;
        let (options, value) = self
            .facade
            .membership()
            .begin_login(user, request.credential.into())
            .await
            .map_err(|_| Error::Unauthorized)?;
        let id = token();
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
            options: serde_json::to_value(options).map_err(|_| Error::Unavailable)?,
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
            .map_err(|_| Error::Unauthorized)?;
        let id = token();
        self.logins.insert(
            id.clone(),
            PendingLogin {
                value,
                until: now + 300,
            },
        );
        Ok(DiscoverableCeremony {
            ceremony: id,
            options: serde_json::to_value(options).map_err(|_| Error::Unavailable)?,
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
        let credential = request.credential.raw_id.clone().into();
        let login = self
            .facade
            .membership()
            .finish_login(pending.value, request.credential)
            .await
            .map_err(|_| Error::Unauthorized)?;
        let user = login.authentication.member();
        let expires = now + self.config.session_seconds;
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
            .map_err(|_| Error::Refused)?;
        serde_json::from_value(
            policy
                .content
                .get("handles.reserved")
                .cloned()
                .ok_or(Error::Unavailable)?,
        )
        .map_err(|_| Error::Unavailable)
    }
    pub async fn lobby(&self, auth: &ckyh::Authentication, now: u64) -> Result<Lobby> {
        use cgts::Gate;
        let policy = self.facade.policy().lock().await;
        let settings = policy
            .published(cplc::SnapshotKind::Settings, now)
            .await
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Unavailable)?;
        let snapshot = cplc::verify_settings(
            policy.key_ring().map_err(|_| Error::Unavailable)?,
            &settings,
            cplc::SnapshotExpectation {
                community: &self.config.community,
                kind: cplc::SnapshotKind::Settings,
                minimum_revision: 1,
                policy_epoch: policy.epoch(now).await.map_err(|_| Error::Unavailable)?,
                now,
            },
        )
        .map_err(|_| Error::Unavailable)?;
        let row = self
            .facade
            .membership()
            .resume(auth)
            .await
            .map_err(|_| Error::Refused)?;
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
            .map_err(|_| Error::Refused)?;
        let lobby = self
            .facade
            .membership()
            .lobby(auth, &*policy, &snapshot, &gates)
            .await
            .map_err(|_| Error::Refused)?;
        let steps = self
            .facade
            .gates()
            .steps(context, &[self.voucher.descriptor()])
            .await
            .map_err(|_| Error::Refused)?;
        let handle = self
            .facade
            .membership()
            .handle(auth)
            .await
            .map_err(|_| Error::Refused)?
            .map(|h| h.display().to_owned());
        Ok(Lobby {
            member_id: lobby.enrolment.subject().into(),
            state: serde_json::to_value(lobby.enrolment.state())
                .map_err(|_| Error::Unavailable)?
                .as_str()
                .ok_or(Error::Unavailable)?
                .into(),
            handle,
            missing: serde_json::to_value(lobby.decision.missing)
                .map_err(|_| Error::Unavailable)?,
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
            .map_err(|_| Error::Refused)?;
        let policy = self
            .facade
            .snapshot(now)
            .await
            .map_err(|_| Error::Refused)?;
        let input: <cgts::gates::VoucherGate as cgts::Gate>::Input =
            serde_json::from_value(serde_json::to_value(request).map_err(|_| Error::Invalid)?)
                .map_err(|_| Error::Invalid)?;
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
            .map_err(|_| Error::Refused)?;
        Ok(())
    }
    pub async fn issue(
        &mut self,
        auth: &ckyh::Authentication,
        request: CredentialRequest,
        withdrawal: Option<(String, String)>,
        now: u64,
    ) -> Result<CredentialResponse> {
        use chrono::Datelike;
        self.refresh_global(now).await?;
        self.prune(now);
        let challenge = self
            .challenges
            .remove(&request.presentation.challenge)
            .ok_or(Error::Refused)?;
        if challenge.owner != Some(auth.member()) {
            return Err(Error::Forbidden);
        }
        let proof = cpsd::Presentation::from_bytes(&request.presentation.proof)
            .map_err(|_| Error::Invalid)?;
        let date = chrono::DateTime::from_timestamp(now as i64, 0)
            .ok_or(Error::Invalid)?
            .checked_add_months(chrono::Months::new(self.config.lease_months))
            .ok_or(Error::Invalid)?;
        let lease = cmbr::YearMonth::new(date.year() as u16, date.month() as u8)
            .map_err(|_| Error::Invalid)?;
        let result = self
            .facade
            .finish_with(
                &mut cpsd::rand::rngs::OsRng,
                &challenge.value,
                &proof,
                cmty::Admission {
                    authentication: auth,
                    devices: &request.devices,
                    lease,
                },
                now,
                async |gates, context| {
                    if let Some((gate, provider)) = withdrawal {
                        gates.withdraw(context.subject, &gate, &provider).await?;
                    }
                    Ok(Vec::new())
                },
            )
            .await
            .map_err(|_| Error::Refused)?;
        let credential = match result {
            cmty::Outcome::Issued(value) => Some(value.cose),
            cmty::Outcome::Missing(_) => None,
            cmty::Outcome::Vetoed => return Err(Error::Forbidden),
        };
        if self
            .facade
            .flush_revocations(now)
            .await
            .map_err(|_| Error::Unavailable)?
            > 0
        {
            self.refresh(now).await?;
        }
        let lobby = self.lobby(auth, now).await?;
        Ok(CredentialResponse { credential, lobby })
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
            .map_err(|_| Error::Unavailable)?;
        self.facade
            .membership()
            .maintain(100)
            .await
            .map_err(|_| Error::Unavailable)?;
        self.facade
            .flush_revocations(now)
            .await
            .map_err(|_| Error::Unavailable)?;
        let policy = self.facade.policy().lock().await;
        let epoch = policy.epoch(now).await.map_err(|_| Error::Unavailable)?;
        let fresh = policy
            .key_ring()
            .map_err(|_| Error::Unavailable)?
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
        .map_err(|_| Error::Unavailable)?;
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
    })
}
