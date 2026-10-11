#![allow(dead_code)]
use cpmt::payments::Result;
use crpt::facilitator::{DispatchGuard, Exchange, Transport};
use cvld::payments::{self, *};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use x402_types::proto::*;

mod wire;
pub use wire::*;

pub const NOW: u64 = 100;
#[derive(Clone)]
pub struct Time(pub Arc<AtomicU64>);
impl Time {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(NOW)))
    }
    pub fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}
impl cpmt::cost::Clock for Time {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
impl cvld::service::Clock for Time {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub fn terms() -> Value {
    json!({"scheme":"exact","network":"eip155:8453","amount":"100","asset":"fixture-asset","payTo":"fixture-merchant","maxTimeoutSeconds":30,"extra":null})
}
pub fn offer() -> Value {
    json!({"x402Version":2,"resource":{"url":"https://merchant.example.test/access"},"accepts":[terms()]})
}
pub fn payload() -> Vec<u8> {
    serde_json::to_vec(&json!({"x402Version":2,"resource":{"url":"https://merchant.example.test/access"},"accepted":terms(),"payload":{"signature":"PRIVATE-SIGNATURE","authorization":{"from":"PRIVATE-PAYER","nonce":"PRIVATE-NONCE"}}})).unwrap()
}
pub fn amount(atoms: u64) -> Amount {
    Amount {
        unit: "fixture-fee".into(),
        scale: 0,
        atoms,
    }
}
pub fn config(path: &std::path::Path) -> PaymentConfig {
    let key = path.join("payment-key");
    std::fs::write(&key, [9; 32]).unwrap();
    PaymentConfig {
        id: "paid-access".into(),
        provider: "fixture-facilitator".into(),
        gate: "crpt".into(),
        account: "operator-account".into(),
        facilitator_url: "https://facilitator.example.test".into(),
        authentication_file: None,
        journal_key_file: key.to_str().unwrap().into(),
        offer: offer(),
        access: AccessTerms {
            level: "caller-level".into(),
            starts_at: 0,
            expires_at: 864000,
        },
        tariff: Tariff {
            coverage: Coverage::AllAcceptedRequests,
            maximum: amount(4),
            exact: false,
            source: "explicit fixture tariff".into(),
            scope: "all configured phase requests, all failures".into(),
            valid_until: 200,
        },
        budget: amount(12),
        capacity: 8,
        ceremony_seconds: 60,
        input_bytes: 65536,
        response_bytes: 65536,
        record_bytes: 65536,
        transport_timeout_seconds: 2,
    }
}
pub fn owner(subject: &str) -> Owner {
    Owner {
        subject: subject.into(),
        user: ckyh::Uuid::from_bytes([1; 16]),
        session: [2; 32],
        credential: vec![3].into(),
    }
}
pub async fn db(path: &std::path::Path) -> crlt::Db {
    let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
        .await
        .unwrap();
    db.migrate(&[crlt::Migration::new(
        1,
        "payment-operations",
        payments::state::SCHEMA,
    )])
    .await
    .unwrap();
    db
}
pub struct Authority {
    pub clock: Time,
    pub calls: AtomicUsize,
    pub refuse_at: usize,
}
impl payments::transport::PhaseAuthority for Authority {
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64>> + Send + '_>> {
        Box::pin(async {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == self.refuse_at {
                Err(cpmt::payments::Error::Rejected)
            } else {
                Ok(cpmt::cost::Clock::now(&self.clock))
            }
        })
    }
}
pub fn authority(clock: Time) -> Arc<Authority> {
    Arc::new(Authority {
        clock,
        calls: AtomicUsize::new(0),
        refuse_at: usize::MAX,
    })
}

pub async fn open_host(
    database: &crlt::Db,
    config: PaymentConfig,
    clock: Time,
    wire: Arc<Wire>,
) -> PaymentHost {
    PaymentHost::open(
        database,
        config,
        "alpha".into(),
        "admission".into(),
        Arc::new(clock),
        Some(payments::transport::AnyTransport(Arc::new(Inert(wire)))),
    )
    .await
    .unwrap()
}
pub fn prepare(host: &mut PaymentHost, owner: &Owner) -> PaymentPreview {
    host.prepare(
        PreparationContext {
            owner: owner.clone(),
            session_expires: 190,
            observed: NOW,
            policy: PolicyBinding {
                epoch: 1,
                revision: 1,
            },
        },
        "paid-access",
        payload(),
        amount(12),
    )
    .unwrap()
}

pub fn instruction(id: [u8; 32]) -> cpmt::payments::Instruction {
    cpmt::payments::Instruction {
        kind: cpmt::payments::Action::Execute,
        id,
        parent: None,
        adapter: "fixture-facilitator".into(),
        operation: "x402.settle".into(),
        binding: cpmt::payments::Binding {
            scope: "alpha".into(),
            subject: "member".into(),
            action: "admission".into(),
        },
        expires_at: 190,
        terms: cpmt::payments::Private::new(serde_json::to_vec(&offer()).unwrap()),
        evidence: cpmt::payments::Private::new(payload()),
    }
}
pub fn fee(atoms: u64) -> cpmt::cost::Amount {
    cpmt::cost::Amount {
        unit: cpmt::cost::Unit {
            code: "fixture-fee".into(),
            scale: 0,
        },
        atoms,
    }
}
pub async fn domain(
    database: &crlt::Db,
    config: &PaymentConfig,
    clock: Time,
    wire: Arc<Wire>,
) -> cpmt::payments::Payments<payments::state::DurableJournal> {
    let mut key = [9; 32];
    let identity = cpmt::payments::account_identity(
        &mut key,
        "alpha",
        &config.provider,
        &config.account,
        &config.facilitator_url,
        cpmt::cost::Mode::Production,
    )
    .unwrap();
    let journal = payments::state::DurableJournal::new(
        database,
        "alpha",
        &identity,
        &config.budget,
        config.capacity,
        config.record_bytes,
        Arc::new(clock.clone()),
    )
    .await
    .unwrap();
    let mut domain = cpmt::payments::Payments::new(journal, [9; 32], Arc::new(clock)).unwrap();
    domain
        .register(Arc::new(
            crpt::x402::X402::new(
                config.provider.clone(),
                Inert(wire),
                config.input_bytes,
                cpmt::cost::Mode::Production,
            )
            .unwrap(),
        ))
        .unwrap();
    domain
}
pub fn permit(
    domain: &cpmt::payments::Payments<payments::state::DurableJournal>,
    request: &cpmt::payments::Instruction,
) -> cpmt::cost::DispatchPermit<String> {
    let quote = domain
        .preview(
            request,
            cpmt::cost::Price::AtMost(fee(4)),
            "explicit fixture tariff".into(),
            200,
        )
        .unwrap();
    cpmt::cost::Plan::new(
        vec![cpmt::cost::Offer {
            candidate: cpmt::cost::Candidate::new(
                request.adapter.clone(),
                [request.operation.clone()],
            ),
            quote,
        }],
        cpmt::cost::Config::new([request.adapter.clone()], [request.operation.clone()]),
        cpmt::cost::CostOrder::Configured,
        fee(12),
        1,
        cpmt::cost::Mode::Production,
        NOW,
    )
    .unwrap()
    .start()
    .begin(NOW)
    .unwrap()
}
