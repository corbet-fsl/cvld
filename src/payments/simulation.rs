//! Pure scenarios using real payment planning and paid-access transformation.
use super::{AccessTerms, Amount, Error, PaymentOutcome, Result};
use cpmt::{
    cost,
    payments::{Action, Binding, Instruction, Private, State},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DummyOutcome {
    Settled,
    Refused,
    Pending,
    Uncertain,
}
impl DummyOutcome {
    fn domain(self) -> State {
        match self {
            Self::Settled => State::Settled,
            Self::Refused => State::Failed,
            Self::Pending => State::Pending,
            Self::Uncertain => State::Unknown,
        }
    }
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SimulationRequest {
    /// Explicit dummy terms/evidence remain transient. No provider is accepted.
    pub dummy_offer: serde_json::Value,
    pub dummy_payload: Vec<u8>,
    pub access: AccessTerms,
    pub maximum: Option<Amount>,
    pub actual_fee: Option<Amount>,
    pub budget: Amount,
    pub source: String,
    pub expires_at: u64,
    pub outcome: DummyOutcome,
    pub satisfies_terms: bool,
}
#[derive(Serialize, ToSchema)]
pub struct SimulationResponse {
    pub simulated: bool,
    pub outcome: PaymentOutcome,
    pub exposure: Amount,
    pub access: Option<AccessTerms>,
    pub charge_violation: bool,
}
pub fn simulate(request: SimulationRequest, now: u64) -> Result<SimulationResponse> {
    if request.dummy_payload.len() > 65536 || request.source.len() > 2048 {
        return Err(Error::Input);
    }
    let offer: crpt::x402::Offer =
        serde_json::from_value(request.dummy_offer.clone()).map_err(|_| Error::Input)?;
    crpt::x402::payment_required(&offer).map_err(|_| Error::Input)?;
    let terms = serde_json::to_vec(&request.dummy_offer).map_err(|_| Error::Input)?;
    if terms.len().saturating_add(request.dummy_payload.len()) > 65536 {
        return Err(Error::Input);
    }
    let instruction = Instruction {
        kind: Action::Execute,
        id: [1; 32],
        parent: None,
        adapter: "simulation".into(),
        operation: "x402.settle".into(),
        binding: Binding {
            scope: "simulation".into(),
            subject: "dummy".into(),
            action: "dummy".into(),
        },
        expires_at: request.expires_at,
        terms: Private::new(terms),
        evidence: Private::new(request.dummy_payload),
    };
    let price = match request.maximum {
        Some(amount) => cost::Price::AtMost(amount.domain()?),
        None => cost::Price::Unknown,
    };
    let quote = cost::Quote {
        price,
        source: request.source,
        valid_until: request.expires_at,
        binding: cost::binding(&instruction, cost::Mode::Simulation),
    };
    let plan = cost::Plan::new(
        vec![cost::Offer {
            candidate: cost::Candidate::new("simulation".into(), ["x402.settle".into()]),
            quote,
        }],
        cost::Config::new(["simulation".into()], ["x402.settle".into()]),
        cost::CostOrder::Configured,
        request.budget.domain()?,
        1,
        cost::Mode::Simulation,
        now,
    )
    .map_err(|_| Error::Budget)?;
    let state = request.outcome.domain();
    let scenario = cpmt::simulation::simulate(
        plan,
        &[cpmt::simulation::Fixture {
            instruction,
            requires: State::Settled,
            state,
            actual_cost: request
                .actual_fee
                .map(|amount| amount.domain())
                .transpose()?,
        }],
        now,
    );
    let outcome = match scenario.stop {
        cpmt::run::Stop::Outcome(cost::Outcome::Success) => PaymentOutcome::Settled,
        cpmt::run::Stop::Outcome(cost::Outcome::Pending) => PaymentOutcome::Pending,
        cpmt::run::Stop::Outcome(cost::Outcome::Uncertain) => PaymentOutcome::Uncertain,
        _ => PaymentOutcome::Refused,
    };
    let access = if outcome == PaymentOutcome::Settled && scenario.charge_violation.is_none() {
        let projected = cpmt::access::simulate_access(
            request.access.domain()?,
            state,
            request.satisfies_terms,
            None,
            now,
        )
        .map_err(|_| Error::Refused)?;
        Some(AccessTerms {
            level: projected.level,
            starts_at: projected.period.start,
            expires_at: projected.period.end,
        })
    } else {
        None
    };
    Ok(SimulationResponse {
        simulated: true,
        outcome,
        exposure: Amount::from_domain(&scenario.exposure),
        access,
        charge_violation: scenario.charge_violation.is_some(),
    })
}
