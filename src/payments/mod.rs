//! Configured x402 paid access. Protocol/payment meaning stays in crpt/cpmt.
mod config;
mod execution;
mod planning;
pub mod simulation;
pub mod state;
pub mod transport;
pub use config::{AccessTerms, Amount, Coverage, PaymentConfig, Tariff};
use cpmt::cost::Clock as _;
use cpmt::{
    access, cost,
    payments::{Binding, Instruction, Payments, Private, State},
};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use utoipa::ToSchema;

/// Keep every actual observation made by the domain, durable reservation and
/// transport. An older admission sample cannot hide a later awaited-boundary
/// observation; once rollback is observed this instance refuses paid work.
pub(crate) struct ObservedClock {
    source: Arc<dyn cost::Clock>,
    observed: std::sync::atomic::AtomicU64,
    invalid: std::sync::atomic::AtomicBool,
}
impl ObservedClock {
    fn new(source: Arc<dyn cost::Clock>) -> Self {
        Self {
            observed: std::sync::atomic::AtomicU64::new(source.now()),
            source,
            invalid: false.into(),
        }
    }
    pub(crate) fn valid(&self) -> bool {
        !self.invalid.load(std::sync::atomic::Ordering::SeqCst)
    }
}
impl cost::Clock for ObservedClock {
    fn now(&self) -> u64 {
        use std::sync::atomic::Ordering;
        let now = self.source.now();
        let previous = self.observed.fetch_max(now, Ordering::SeqCst);
        if now < previous {
            self.invalid.store(true, Ordering::SeqCst);
        }
        now
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid payment configuration")]
    Configuration,
    #[error("invalid payment input")]
    Input,
    #[error("payment budget refused")]
    Budget,
    #[error("payment ceremony expired")]
    Expired,
    #[error("payment capacity reached")]
    Capacity,
    #[error("payment operation conflict")]
    Conflict,
    #[error("payment operation refused")]
    Refused,
    #[error("payment storage unavailable")]
    Storage,
    #[error("payment outcome requires reconciliation")]
    Uncertain,
}
pub type Result<T> = std::result::Result<T, Error>;
fn payment_error(error: cpmt::payments::Error) -> Error {
    match error {
        cpmt::payments::Error::Cost => Error::Budget,
        cpmt::payments::Error::Expired => Error::Expired,
        cpmt::payments::Error::Conflict => Error::Conflict,
        cpmt::payments::Error::Storage => Error::Storage,
        _ => Error::Refused,
    }
}

/// Constructed by the trusted host from the original genuine authentication.
/// No caller subject/session/key can be supplied by member JSON.
#[derive(Clone, PartialEq, Eq)]
pub struct Owner {
    pub subject: String,
    pub user: ckyh::Uuid,
    pub session: [u8; 32],
    pub credential: ckyh::CredentialID,
}
/// Trusted original policy snapshot used when the exact paid operation was
/// prepared. Current reads must match it before any protocol phase or accept.
#[derive(Clone, Copy)]
pub struct PolicyBinding {
    pub epoch: u64,
    pub revision: u64,
}
/// Trusted authentication and policy observations captured for preparation.
/// These fields are host inputs, never part of the member's payment request.
pub struct PreparationContext {
    pub owner: Owner,
    pub session_expires: u64,
    pub observed: u64,
    pub policy: PolicyBinding,
}
pub struct ExecutionContext {
    pub policy: PolicyBinding,
    pub expires_at: u64,
    pub observed: u64,
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentOutcome {
    Prepared,
    Settled,
    Refused,
    Pending,
    Uncertain,
}
#[derive(Clone, Serialize, ToSchema)]
pub struct PaymentPreview {
    pub operation: String,
    pub authorization: String,
    pub option: String,
    pub access: AccessTerms,
    pub maximum: Amount,
    pub budget: Amount,
    pub exact: bool,
    pub source: String,
    pub scope: String,
    pub expires_at: u64,
}
#[derive(Clone, Serialize, ToSchema)]
pub struct PaymentReceipt {
    pub operation: String,
    pub outcome: PaymentOutcome,
    /// Set only after the actual domain establishes exact settled terms.
    pub access: Option<AccessTerms>,
}

enum Phase {
    Prepared,
    Running,
    Finished(PaymentReceipt),
}
struct Flow {
    owner: Owner,
    instruction: Option<Instruction>,
    id: [u8; 32],
    binding: Binding,
    preview: PaymentPreview,
    phase: Phase,
    access: Option<access::PaidAccess>,
    until: u64,
    observed: u64,
    started: Instant,
    lifetime: Duration,
    policy: PolicyBinding,
}

pub struct PaymentHost {
    domain: Payments<state::DurableJournal>,
    phase_transport: transport::GuardedTransport,
    config: PaymentConfig,
    scope: String,
    action: String,
    clock: Arc<ObservedClock>,
    flows: HashMap<String, Flow>,
}
impl PaymentHost {
    /// Explicit host loading and atomic stable account/key binding precede any
    /// planning. Rust injection replaces only external protocol transport.
    pub async fn open(
        db: &crlt::Db,
        config: PaymentConfig,
        scope: String,
        action: String,
        clock: Arc<dyn cost::Clock>,
        injected: Option<transport::AnyTransport>,
    ) -> Result<Self> {
        config.validate(clock.now())?;
        let key = crate::config::Config::seed(&config.journal_key_file)
            .map_err(|_| Error::Configuration)?;
        let mut key_copy = key;
        let identity = cpmt::payments::account_identity(
            &mut key_copy,
            &scope,
            &config.provider,
            &config.account,
            &config.facilitator_url,
            cost::Mode::Production,
        )
        .map_err(payment_error)?;
        let journal = state::DurableJournal::new(
            db,
            &scope,
            &identity,
            &config.budget,
            config.capacity,
            config.record_bytes,
            clock.clone(),
        )
        .await?;
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(path) = &config.authentication_file {
            let bytes = crate::config::Config::secret(path).map_err(|_| Error::Configuration)?;
            if bytes.len() > config.input_bytes {
                return Err(Error::Configuration);
            }
            let configured: std::collections::BTreeMap<String, String> =
                serde_json::from_slice(&bytes).map_err(|_| Error::Configuration)?;
            for (name, value) in configured {
                let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| Error::Configuration)?;
                let mut value = reqwest::header::HeaderValue::from_str(&value)
                    .map_err(|_| Error::Configuration)?;
                value.set_sensitive(true);
                headers.insert(name, value);
            }
        }
        let wire = match injected {
            Some(wire) => wire,
            None => transport::AnyTransport(Arc::new(
                crpt::http::HttpFacilitator::new(
                    reqwest::Url::parse(&config.facilitator_url)
                        .map_err(|_| Error::Configuration)?,
                    headers,
                    Duration::from_secs(config.transport_timeout_seconds),
                    config.response_bytes,
                )
                .map_err(payment_error)?,
            )),
        };
        Self::with_transport(journal, key, config, scope, action, clock, wire)
    }
    /// Production host supplies its actual durable Journal and stable key. An
    /// injected transport replaces only original external protocol messages.
    fn with_transport(
        mut journal: state::DurableJournal,
        key: [u8; 32],
        config: PaymentConfig,
        scope: String,
        action: String,
        clock: Arc<dyn cost::Clock>,
        wire: transport::AnyTransport,
    ) -> Result<Self> {
        let clock = Arc::new(ObservedClock::new(clock));
        config.validate(clock.now())?;
        if !clock.valid() {
            return Err(Error::Expired);
        }
        journal.use_clock(clock.clone());
        config::text(&scope, 256)?;
        config::text(&action, 256)?;
        let guarded = transport::GuardedTransport::new(wire);
        let adapter = crpt::x402::X402::new(
            config.provider.clone(),
            guarded.clone(),
            config.input_bytes,
            cost::Mode::Production,
        )
        .map_err(payment_error)?;
        let mut domain = Payments::new(journal, key, clock.clone()).map_err(payment_error)?;
        domain.register(Arc::new(adapter)).map_err(payment_error)?;
        Ok(Self {
            domain,
            phase_transport: guarded,
            config,
            scope,
            action,
            clock,
            flows: HashMap::new(),
        })
    }
    pub fn config(&self) -> &PaymentConfig {
        &self.config
    }
}
