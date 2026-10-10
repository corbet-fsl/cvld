//! Production contacts compose real leaves with caller-selected, bounded costs.
//! Private preparations, pending sessions and typed facts live only in RAM.
pub mod config;
pub mod simulation;
pub mod state;
pub mod transport;
use crate::service::Clock;
use cfbk::cost;
use cgbl::{
    CheckId, GateEvidence, GlobalGate, Subject,
    contacts::{ContactBinding, MailboxGate, PhoneGate},
};
pub use config::{Amount, Channel, ContactConfig, Coverage, Order, ProviderConfig, Tariff};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use utoipa::ToSchema;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid contact configuration")]
    Configuration,
    #[error("invalid contact input")]
    Input,
    #[error("contact cost authorization refused")]
    Budget,
    #[error("contact operation unavailable")]
    Conflict,
    #[error("contact operation expired")]
    Expired,
    #[error("contact verification refused")]
    Refused,
    #[error("contact outcome uncertain; reconcile before another dispatch")]
    Uncertain,
    #[error("contact operational state unavailable")]
    Storage,
    #[error("contact preparation capacity exhausted")]
    Capacity,
    #[error("contact comparison keys require explicit migration")]
    Migration,
}
pub type Result<T> = std::result::Result<T, Error>;
/// The trusted door rechecks live authentication and actual domain policy after
/// awaited reservation, immediately before leaf dispatch. No member callback.
pub type DispatchCheck<'a> = dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64>> + Send + 'a>>
    + Send
    + Sync
    + 'a;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Pending,
    Verified,
    SafeFailure,
    Refused,
    Uncertain,
}
impl Outcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::SafeFailure => "safe_failure",
            Self::Refused => "refused",
            Self::Uncertain => "uncertain",
        }
    }
    fn domain(self) -> cost::Outcome {
        match self {
            Self::Pending => cost::Outcome::Pending,
            Self::Verified => cost::Outcome::Success,
            Self::SafeFailure => cost::Outcome::SafeFailure,
            Self::Refused => cost::Outcome::Refused,
            Self::Uncertain => cost::Outcome::Uncertain,
        }
    }
}
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct Offer {
    pub coverage: Coverage,
    pub option: String,
    pub channel: Channel,
    pub maximum: Amount,
    pub exact: bool,
    pub source: String,
    pub scope: String,
    pub valid_until: u64,
}
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct Preview {
    pub operation: String,
    /// Consent identifies this exact preview generation. Beginning a later OTP
    /// check invalidates consent from the previous begin/check preparation.
    pub authorization: String,
    pub offers: Vec<Offer>,
    pub excluded: Vec<String>,
    pub budget: Amount,
    pub max_attempts: usize,
    pub valid_until: u64,
}
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct Receipt {
    pub operation: String,
    pub outcome: Outcome,
    /// Conservative reserved exposure, never an invented actual charge.
    pub exposure: Amount,
}

/// Independently authenticated account and session, supplied by the door.
/// This owner is checked for every RAM continuation and never serialized.
#[derive(Clone, PartialEq, Eq)]
pub struct Owner {
    pub subject: Subject,
    pub session: [u8; 32],
}

/// Caller-chosen limits, fixed across a ceremony. No policy defaults.
pub struct Constraints {
    /// The independently chosen original global check, never derived from a fact.
    pub check: CheckId,
    pub budget: Amount,
    pub max_attempts: usize,
    pub order: Order,
    pub pending_expires_at: u64,
    pub fact_expires_at: u64,
}

struct Provider {
    config: ProviderConfig,
    adapter: Adapter,
}
enum Adapter {
    Phone(cphn::Twilio),
    Mailbox(cmbx::Twilio),
}
enum Prepared {
    Phone(cphn::Prepared),
    Mailbox(cmbx::Prepared),
}
impl Prepared {
    fn binding(&self) -> &str {
        match self {
            Self::Phone(p) => p.binding(),
            Self::Mailbox(p) => p.binding(),
        }
    }
}
enum Pending {
    Phone(cphn::Pending),
    Mailbox(cmbx::Pending),
}
enum Step {
    Pending(Pending),
    Verified(Gate),
}
struct Attempt {
    option: usize,
    binding: ContactBinding,
    leaf_binding: [u8; 32],
    operation: [u8; 32],
    prepared: Prepared,
    tariff: Tariff,
}
enum Status {
    Prepared {
        authorization: String,
        attempts: Vec<Option<Attempt>>,
        plan: cost::Plan<usize, &'static str>,
    },
    Pending {
        option: usize,
        binding: ContactBinding,
        leaf_binding: [u8; 32],
        pending: Box<Pending>,
    },
    Verified(Gate),
    Stopped(Outcome),
}
struct Flow {
    check: CheckId,
    owner: Owner,
    ceremony: [u8; 32],
    budget: Amount,
    max_attempts: usize,
    expires_at: u64,
    fact_expires_at: u64,
    floor: u64,
    status: Status,
}

/// A real leaf gate retains no destination or OTP. Facade retries use this fact
/// without calling a provider; simulation has no constructor for this type.
pub enum Gate {
    Phone(PhoneGate),
    Mailbox(MailboxGate),
}
impl Gate {
    pub fn input(&self) -> &[u8] {
        match self {
            Self::Phone(p) => p.input(),
            Self::Mailbox(p) => p.input(),
        }
    }
}
impl GlobalGate for Gate {
    fn id(&self) -> &str {
        match self {
            Self::Phone(p) => p.id(),
            Self::Mailbox(p) => p.id(),
        }
    }
    fn provider(&self) -> &str {
        match self {
            Self::Phone(p) => p.provider(),
            Self::Mailbox(p) => p.provider(),
        }
    }
    fn development_only(&self) -> bool {
        false
    }
    async fn verify(
        &self,
        check: &CheckId,
        subject: &Subject,
        input: &[u8],
        now: u64,
    ) -> cgbl::Result<GateEvidence> {
        match self {
            Self::Phone(p) => p.verify(check, subject, input, now).await,
            Self::Mailbox(p) => p.verify(check, subject, input, now).await,
        }
    }
}

pub struct Contacts<T = transport::AnyTransport> {
    providers: Vec<Provider>,
    phone_key: Option<Zeroizing<[u8; 32]>>,
    mailbox_key: Option<Zeroizing<[u8; 32]>>,
    ledger: state::Ledger,
    transport: T,
    clock: Arc<dyn Clock>,
    capacity: usize,
    budget_cap: Amount,
    attempt_cap: usize,
    flows: BTreeMap<String, Flow>,
}
impl Contacts {
    pub async fn configured(
        db: &crlt::Db,
        scope: &str,
        config: &ContactConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let transport =
            transport::HttpTransport::new(clock.clone(), config.transport_timeout_seconds)?;
        Self::with_transport(
            db,
            scope,
            config,
            clock,
            transport::AnyTransport::new(Arc::new(transport)),
        )
        .await
    }
}
impl<T: cphn::Transport + cmbx::Transport> Contacts<T> {
    /// Trusted transport injection exists for inert HTTP contract tests. Member
    /// data cannot select a transport, endpoint, credential file or identity key.
    pub async fn with_transport(
        db: &crlt::Db,
        scope: &str,
        config: &ContactConfig,
        clock: Arc<dyn Clock>,
        transport: T,
    ) -> Result<Self> {
        if config.capacity == 0
            || config.ceremony_seconds == 0
            || config.max_attempts == 0
            || i64::try_from(config.max_attempts).is_err()
            || cphn::Transport::mode(&transport) != cost::Mode::Production
            || cmbx::Transport::mode(&transport) != cost::Mode::Production
        {
            return Err(Error::Configuration);
        }
        config.budget.domain()?;
        let key = |path: &Option<String>| -> Result<Option<Zeroizing<[u8; 32]>>> {
            path.as_ref()
                .map(|path| {
                    crate::config::Config::seed(path)
                        .map(Zeroizing::new)
                        .map_err(|_| Error::Configuration)
                })
                .transpose()
        };
        let phone_key = key(&config.phone_identity_key_file)?;
        let mailbox_key = key(&config.mailbox_identity_key_file)?;
        let mut providers = Vec::<Provider>::new();
        for cfg in &config.providers {
            if cfg.id.is_empty()
                || cfg.id.len() > 128
                || !cfg
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
                || cfg.provider.is_empty()
                || cfg.provider.len() > 128
                || !cfg
                    .provider
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
                || providers.iter().any(|p| p.config.id == cfg.id)
            {
                return Err(Error::Configuration);
            }
            cfg.begin.price(clock.now())?;
            cfg.check.price(clock.now())?;
            let secret = crate::config::Config::secret(&cfg.credential_file)
                .map_err(|_| Error::Configuration)?;
            let adapter = if cfg.channel == Channel::Email {
                if mailbox_key.is_none() {
                    return Err(Error::Configuration);
                }
                Adapter::Mailbox(
                    cmbx::Twilio::new(
                        cfg.account.clone(),
                        cfg.service.clone(),
                        cmbx::Private::new(secret.to_vec()),
                        cost::Mode::Production,
                    )
                    .map_err(|_| Error::Configuration)?,
                )
            } else {
                if phone_key.is_none() {
                    return Err(Error::Configuration);
                }
                Adapter::Phone(
                    cphn::Twilio::new(
                        cfg.account.clone(),
                        cfg.service.clone(),
                        cphn::Private::new(secret.to_vec()),
                        cost::Mode::Production,
                    )
                    .map_err(|_| Error::Configuration)?,
                )
            };
            providers.push(Provider {
                config: cfg.clone(),
                adapter,
            });
        }
        let ledger = state::Ledger::new(db, scope, clock.clone())?;
        let mut bindings = Vec::new();
        for (domain, key) in [
            (cgbl::contacts::ContactDomain::Phone, &phone_key),
            (cgbl::contacts::ContactDomain::Mailbox, &mailbox_key),
        ] {
            if let Some(key) = key {
                let mut copy = **key;
                let commitment = cgbl::contacts::comparison_key_binding(scope, domain, &mut copy)
                    .map_err(|_| Error::Configuration)?;
                bindings.push(state::ComparisonBinding { domain, commitment });
            }
        }
        ledger.bind_comparison_keys(scope, &bindings).await?;
        Ok(Self {
            providers,
            phone_key,
            mailbox_key,
            ledger,
            transport,
            clock,
            capacity: config.capacity,
            budget_cap: config.budget.clone(),
            attempt_cap: config.max_attempts,
            flows: BTreeMap::new(),
        })
    }
    pub fn providers(&self) -> impl Iterator<Item = (&str, &str, Channel)> {
        self.providers.iter().map(|p| {
            (
                p.config.id.as_str(),
                p.config.provider.as_str(),
                p.config.channel,
            )
        })
    }
    /// The caller prepares each binding through its actual cgbl facade for the
    /// authenticated subject/check and the configured gate/provider. Options
    /// here must share one domain; phone and mailbox are never substitutes.
    pub fn prepare_begin(
        &mut self,
        owner: Owner,
        selections: Vec<(String, ContactBinding)>,
        destination: &str,
        constraints: Constraints,
    ) -> Result<Preview> {
        let Constraints {
            check,
            budget,
            max_attempts,
            order,
            pending_expires_at,
            fact_expires_at,
        } = constraints;
        let requested = budget.domain()?;
        let configured = self.budget_cap.domain()?;
        if requested.unit != configured.unit
            || requested.atoms > configured.atoms
            || max_attempts > self.attempt_cap
        {
            return Err(Error::Budget);
        }
        let now = self.clock.now();
        self.flows.retain(|_, flow| now < flow.expires_at);
        if self.flows.len() >= self.capacity {
            return Err(Error::Capacity);
        }
        if destination.len() > 320
            || selections.is_empty()
            || selections.len() > self.providers.len()
            || pending_expires_at <= now
            || pending_expires_at > fact_expires_at
            || fact_expires_at > i64::MAX as u64
        {
            return Err(Error::Input);
        }
        let mut attempts = Vec::new();
        let mut domain = None;
        for (id, binding) in selections {
            let option = self
                .providers
                .iter()
                .position(|p| p.config.id == id)
                .ok_or(Error::Configuration)?;
            if attempts.iter().any(|a: &Attempt| a.option == option) {
                return Err(Error::Configuration);
            }
            let provider = &self.providers[option];
            let gate = provider.config.channel.gate();
            if domain
                .replace(gate)
                .is_some_and(|previous| previous != gate)
            {
                return Err(Error::Configuration);
            }
            let operation = rand::random();
            let (prepared, leaf_binding) = match &provider.adapter {
                Adapter::Phone(adapter) => {
                    let context = binding
                        .phone_context(
                            operation,
                            self.phone_key.as_ref().ok_or(Error::Configuration)?.clone(),
                            fact_expires_at,
                        )
                        .map_err(|_| Error::Configuration)?;
                    let leaf_binding = context.binding;
                    (
                        Prepared::Phone(
                            adapter
                                .prepare_begin(
                                    destination,
                                    provider.config.channel.phone()?,
                                    context,
                                    now,
                                )
                                .map_err(|_| Error::Input)?,
                        ),
                        leaf_binding,
                    )
                }
                Adapter::Mailbox(adapter) => {
                    let context = binding
                        .mailbox_context(
                            operation,
                            self.mailbox_key
                                .as_ref()
                                .ok_or(Error::Configuration)?
                                .clone(),
                            fact_expires_at,
                        )
                        .map_err(|_| Error::Configuration)?;
                    let leaf_binding = context.binding;
                    (
                        Prepared::Mailbox(
                            adapter
                                .prepare_begin(destination, cmbx::Channel::Email, context, now)
                                .map_err(|_| Error::Input)?,
                        ),
                        leaf_binding,
                    )
                }
            };
            attempts.push(Attempt {
                option,
                binding,
                leaf_binding,
                operation,
                prepared,
                tariff: provider.config.begin.clone(),
            });
        }
        let operation = uuid::Uuid::new_v4().to_string();
        let (plan, preview) = self.plan(
            &operation,
            &attempts,
            Constraints {
                check: check.clone(),
                budget: budget.clone(),
                max_attempts,
                order,
                pending_expires_at,
                fact_expires_at,
            },
            now,
        )?;
        self.flows.insert(
            operation,
            Flow {
                check,
                owner,
                ceremony: rand::random(),
                budget,
                max_attempts,
                expires_at: pending_expires_at,
                fact_expires_at,
                floor: now,
                status: Status::Prepared {
                    authorization: preview.authorization.clone(),
                    attempts: attempts.into_iter().map(Some).collect(),
                    plan,
                },
            },
        );
        Ok(preview)
    }
    fn plan(
        &self,
        operation: &str,
        attempts: &[Attempt],
        constraints: Constraints,
        now: u64,
    ) -> Result<(cost::Plan<usize, &'static str>, Preview)> {
        let Constraints {
            budget,
            max_attempts,
            order,
            pending_expires_at: expires_at,
            ..
        } = constraints;
        let mut offers = Vec::new();
        for (index, attempt) in attempts.iter().enumerate() {
            offers.push(cost::Offer {
                candidate: cfbk::Candidate::new(
                    index,
                    [self.providers[attempt.option].config.channel.gate()],
                ),
                quote: cost::Quote {
                    price: attempt.tariff.price(now)?,
                    source: attempt.tariff.source.clone(),
                    valid_until: attempt.tariff.valid_until.min(expires_at),
                    binding: attempt.prepared.binding().into(),
                },
            });
        }
        let minimum = self.providers[attempts.first().ok_or(Error::Input)?.option]
            .config
            .channel
            .gate();
        let plan = cost::Plan::new(
            offers,
            cfbk::Config::new(0..attempts.len(), [minimum]),
            order.domain(),
            budget.domain()?,
            max_attempts,
            cost::Mode::Production,
            now,
        )
        .map_err(|_| Error::Budget)?;
        let offers = plan
            .offers()
            .iter()
            .map(|offer| {
                let a = &attempts[offer.candidate.id];
                Offer {
                    coverage: a.tariff.coverage,
                    option: self.providers[a.option].config.id.clone(),
                    channel: self.providers[a.option].config.channel,
                    maximum: Amount::from_domain(
                        offer
                            .quote
                            .price
                            .maximum()
                            .expect("cfbk admitted a bounded offer"),
                    ),
                    exact: a.tariff.exact,
                    source: a.tariff.source.clone(),
                    scope: a.tariff.scope.clone(),
                    valid_until: offer.quote.valid_until,
                }
            })
            .collect();
        let excluded = plan
            .excluded()
            .iter()
            .map(|(id, reason)| {
                format!(
                    "{}:{reason:?}",
                    self.providers[attempts[*id].option].config.id
                )
            })
            .collect();
        let preview = Preview {
            operation: operation.into(),
            authorization: uuid::Uuid::new_v4().to_string(),
            offers,
            excluded,
            budget,
            max_attempts,
            valid_until: expires_at,
        };
        Ok((plan, preview))
    }
    fn flow(&self, operation: &str, owner: &Owner) -> Result<&Flow> {
        let flow = self
            .flows
            .get(operation)
            .filter(|flow| &flow.owner == owner)
            .ok_or(Error::Conflict)?;
        let now = self.clock.now();
        if now < flow.floor || now >= flow.expires_at {
            return Err(Error::Expired);
        }
        Ok(flow)
    }
    /// A check is separately previewed before it can cost money. The actual OTP
    /// is bounded private input and is consumed by the leaf's real preparation.
    pub fn prepare_check(&mut self, operation: &str, owner: &Owner, code: &str) -> Result<Preview> {
        if !matches!(self.flow(operation, owner)?.status, Status::Pending { .. }) {
            return Err(Error::Conflict);
        }
        if !(4..=10).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Input);
        }
        let now = self.clock.now();
        let mut flow = self.flows.remove(operation).ok_or(Error::Conflict)?;
        let status = std::mem::replace(&mut flow.status, Status::Stopped(Outcome::Uncertain));
        let result = (|| {
            let Status::Pending {
                option,
                binding,
                leaf_binding,
                pending,
            } = status
            else {
                return Err(Error::Conflict);
            };
            let op = rand::random();
            let provider = &self.providers[option];
            let prepared = match (&provider.adapter, *pending) {
                (Adapter::Phone(adapter), Pending::Phone(pending)) => Prepared::Phone(
                    adapter
                        .prepare_check(pending, code, op, now)
                        .map_err(|_| Error::Refused)?,
                ),
                (Adapter::Mailbox(adapter), Pending::Mailbox(pending)) => Prepared::Mailbox(
                    adapter
                        .prepare_check(pending, code, op, now)
                        .map_err(|_| Error::Refused)?,
                ),
                _ => return Err(Error::Configuration),
            };
            let attempts = vec![Attempt {
                option,
                binding,
                leaf_binding,
                operation: op,
                prepared,
                tariff: provider.config.check.clone(),
            }];
            let (plan, preview) = self.plan(
                operation,
                &attempts,
                Constraints {
                    check: flow.check.clone(),
                    budget: flow.budget.clone(),
                    max_attempts: flow.max_attempts,
                    order: Order::Configured,
                    pending_expires_at: flow.expires_at,
                    fact_expires_at: flow.fact_expires_at,
                },
                now,
            )?;
            flow.status = Status::Prepared {
                authorization: preview.authorization.clone(),
                attempts: attempts.into_iter().map(Some).collect(),
                plan,
            };
            flow.floor = now;
            Ok(preview)
        })();
        self.flows.insert(operation.into(), flow);
        result
    }
    /// Execute exactly the RAM-held preview. The action itself is explicit cost
    /// consent; callers must expose the returned preview before invoking it.
    pub async fn execute(
        &mut self,
        operation: &str,
        authorization: &str,
        owner: &Owner,
    ) -> Result<Receipt> {
        let clock = self.clock.clone();
        let check =
            || -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64>> + Send>> {
                Box::pin(std::future::ready(Ok(clock.now())))
            };
        self.execute_checked(operation, authorization, owner, &check)
            .await
    }
    /// Production door entry point. Each possibly dispatched fallback option
    /// remains subject to the door's actual live owner/policy check.
    pub async fn execute_checked(
        &mut self,
        operation: &str,
        authorization: &str,
        owner: &Owner,
        check: &DispatchCheck<'_>,
    ) -> Result<Receipt> {
        if !matches!(&self.flow(operation, owner)?.status, Status::Prepared { authorization: expected, .. } if authorization == expected)
        {
            return Err(Error::Conflict);
        }
        let (
            ceremony,
            budget,
            max_attempts,
            expires_at,
            fact_expires_at,
            mut floor,
            mut attempts,
            plan,
        ) = {
            let flow = self.flows.get_mut(operation).ok_or(Error::Conflict)?;
            let status = std::mem::replace(&mut flow.status, Status::Stopped(Outcome::Uncertain));
            let Status::Prepared { attempts, plan, .. } = status else {
                return Err(Error::Conflict);
            };
            (
                flow.ceremony,
                flow.budget.clone(),
                flow.max_attempts,
                flow.expires_at,
                flow.fact_expires_at,
                flow.floor,
                attempts,
                plan,
            )
        };
        // State becomes uncertain before the first await. Cancellation therefore
        // cannot restore a spent preview or silently dispatch a replacement.
        let mut cascade = plan.start();
        loop {
            let now = self.clock.now();
            if now < floor || now >= expires_at {
                return Err(Error::Expired);
            }
            floor = now;
            let permit = match cascade.begin(now) {
                Ok(permit) => permit,
                Err(_) if cascade.attempts() > 0 && !cascade.is_pending() => {
                    self.flows.get_mut(operation).ok_or(Error::Conflict)?.status =
                        Status::Stopped(Outcome::SafeFailure);
                    return Ok(Receipt {
                        operation: operation.into(),
                        outcome: Outcome::SafeFailure,
                        exposure: self.ledger.exposure(&ceremony).await?,
                    });
                }
                Err(_) => return Err(Error::Budget),
            };
            let attempt = attempts[*permit.candidate()]
                .take()
                .ok_or(Error::Conflict)?;
            let authorized_at = check().await?;
            if authorized_at < floor {
                return Err(Error::Expired);
            }
            floor = authorized_at;
            let maximum = permit.quote().price.maximum().ok_or(Error::Budget)?.clone();
            let mut seal = self
                .ledger
                .reserve(state::Reservation {
                    ceremony,
                    leaf_binding: attempt.leaf_binding,
                    operation: attempt.operation,
                    binding: attempt.prepared.binding().into(),
                    maximum,
                    budget: budget.clone(),
                    max_attempts,
                    ceremony_deadline: expires_at,
                    dispatch_deadline: permit.quote().valid_until.min(fact_expires_at),
                })
                .await?;
            // If this live check refuses, the durable reservation remains and
            // no provider receives the request. Cancellation has the same floor.
            let authorized_at = check().await.map_err(|_| Error::Uncertain)?;
            if authorized_at < floor {
                return Err(Error::Uncertain);
            }
            seal.retain_authorization_floor(authorized_at)?;
            floor = authorized_at;
            let clock = || self.clock.now();
            let result = match attempt.prepared {
                Prepared::Phone(prepared) => prepared
                    .dispatch(&seal, &self.transport, permit, &clock)
                    .await
                    .map_err(phone_error)
                    .and_then(|step| match step {
                        cphn::Step::Pending(pending) => Ok(Step::Pending(Pending::Phone(pending))),
                        cphn::Step::Verified(fact) => PhoneGate::new(attempt.binding.clone(), fact)
                            .map(Gate::Phone)
                            .map(Step::Verified)
                            .map_err(|_| Outcome::Refused),
                    }),
                Prepared::Mailbox(prepared) => prepared
                    .dispatch(&seal, &self.transport, permit, &clock)
                    .await
                    .map_err(mailbox_error)
                    .and_then(|step| match step {
                        cmbx::Step::Pending(pending) => {
                            Ok(Step::Pending(Pending::Mailbox(pending)))
                        }
                        cmbx::Step::Verified(fact) => {
                            MailboxGate::new(attempt.binding.clone(), fact)
                                .map(Gate::Mailbox)
                                .map(Step::Verified)
                                .map_err(|_| Outcome::Refused)
                        }
                    }),
            };
            let outcome = match &result {
                Ok(Step::Pending(_)) => Outcome::Pending,
                Ok(Step::Verified(_)) => Outcome::Verified,
                Err(outcome) => *outcome,
            };
            self.ledger
                .complete(&ceremony, &attempt.operation, outcome)
                .await
                .map_err(|_| Error::Uncertain)?;
            cascade
                .complete(outcome.domain(), None)
                .map_err(|_| Error::Budget)?;
            let completed = self.clock.now();
            if completed < floor || completed >= expires_at {
                return Err(Error::Uncertain);
            }
            floor = completed;
            if outcome == Outcome::SafeFailure {
                continue;
            }
            let flow = self.flows.get_mut(operation).ok_or(Error::Conflict)?;
            flow.floor = floor;
            flow.status = match result {
                Ok(Step::Pending(pending)) => Status::Pending {
                    option: attempt.option,
                    binding: attempt.binding,
                    leaf_binding: attempt.leaf_binding,
                    pending: Box::new(pending),
                },
                Ok(Step::Verified(gate)) => Status::Verified(gate),
                Err(outcome) => Status::Stopped(outcome),
            };
            let exposure = self.ledger.exposure(&ceremony).await?;
            return Ok(Receipt {
                operation: operation.into(),
                outcome,
                exposure,
            });
        }
    }
    /// Actual global verification happens through cgbl after this typed read.
    /// The door retains its own independent live session/publication checks.
    pub fn gate(&self, operation: &str, owner: &Owner) -> Result<&Gate> {
        match &self.flow(operation, owner)?.status {
            Status::Verified(gate) => Ok(gate),
            _ => Err(Error::Conflict),
        }
    }
    pub fn check(&self, operation: &str, owner: &Owner) -> Result<&CheckId> {
        Ok(&self.flow(operation, owner)?.check)
    }
    /// Trusted orchestration context for rechecking every possibly attempted
    /// option before paid work. Contains no destination, code or provider data.
    pub fn execution_context(&self, operation: &str, owner: &Owner) -> Result<(Vec<String>, u64)> {
        let flow = self.flow(operation, owner)?;
        let options = match &flow.status {
            Status::Prepared { attempts, .. } => attempts
                .iter()
                .filter_map(|a| {
                    a.as_ref()
                        .map(|a| self.providers[a.option].config.id.clone())
                })
                .collect(),
            Status::Pending { option, .. } => vec![self.providers[*option].config.id.clone()],
            Status::Verified(gate) => self
                .providers
                .iter()
                .filter(|p| {
                    p.config.channel.gate() == gate.id() && p.config.provider == gate.provider()
                })
                .map(|p| p.config.id.clone())
                .collect(),
            Status::Stopped(_) => return Err(Error::Conflict),
        };
        Ok((options, flow.fact_expires_at))
    }
    pub async fn status(&self, operation: &str, owner: &Owner) -> Result<Receipt> {
        let flow = self.flow(operation, owner)?;
        let outcome = match &flow.status {
            Status::Pending { .. } => Outcome::Pending,
            Status::Verified(_) => Outcome::Verified,
            Status::Stopped(outcome) => *outcome,
            Status::Prepared { .. } => return Err(Error::Conflict),
        };
        Ok(Receipt {
            operation: operation.into(),
            outcome,
            exposure: self.ledger.exposure(&flow.ceremony).await?,
        })
    }
}

fn phone_error(error: cphn::Error) -> Outcome {
    match error {
        cphn::Error::NotDispatched => Outcome::SafeFailure,
        cphn::Error::Input
        | cphn::Error::Configuration
        | cphn::Error::Refused
        | cphn::Error::Budget => Outcome::Refused,
        _ => Outcome::Uncertain,
    }
}
fn mailbox_error(error: cmbx::Error) -> Outcome {
    match error {
        cmbx::Error::NotDispatched => Outcome::SafeFailure,
        cmbx::Error::Input
        | cmbx::Error::Configuration
        | cmbx::Error::Refused
        | cmbx::Error::Budget => Outcome::Refused,
        _ => Outcome::Uncertain,
    }
}

/// Simulation is a separate static entry point: no Contacts, credentials,
/// transport, ledger or genuine proof can be supplied or returned.
pub fn simulate_phone(
    destination: &str,
    scope: &[u8],
    offers: Vec<cphn::SimulationOffer>,
    settings: cphn::SimulationSettings,
) -> Result<cphn::Simulated> {
    cphn::simulate(destination, scope, offers, settings).map_err(|_| Error::Input)
}
pub fn simulate_mailbox(
    destination: &str,
    scope: &[u8],
    offers: Vec<cmbx::SimulationOffer>,
    settings: cmbx::SimulationSettings,
) -> Result<cmbx::Simulated> {
    cmbx::simulate(destination, scope, offers, settings).map_err(|_| Error::Input)
}
