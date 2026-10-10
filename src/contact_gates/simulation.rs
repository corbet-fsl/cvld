//! Public local simulation projections; no production operation is created.
use super::{Amount, Channel, Error, Order, Result};
use cfbk::cost;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SimulationOutcome {
    Success,
    SafeFailure,
    Refused,
    Pending,
    Uncertain,
}
impl SimulationOutcome {
    fn domain(self) -> cost::Outcome {
        match self {
            Self::Success => cost::Outcome::Success,
            Self::SafeFailure => cost::Outcome::SafeFailure,
            Self::Refused => cost::Outcome::Refused,
            Self::Pending => cost::Outcome::Pending,
            Self::Uncertain => cost::Outcome::Uncertain,
        }
    }
    fn from_domain(value: cost::Outcome) -> Self {
        match value {
            cost::Outcome::Success => Self::Success,
            cost::Outcome::SafeFailure => Self::SafeFailure,
            cost::Outcome::Refused => Self::Refused,
            cost::Outcome::Pending => Self::Pending,
            cost::Outcome::Uncertain => Self::Uncertain,
        }
    }
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SimulationOffer {
    pub channel: Channel,
    /// None is unknown; it does not authorize even a hypothetical dispatch.
    pub maximum: Option<Amount>,
    pub exact: bool,
    pub source: String,
    pub valid_until: u64,
    pub outcome: SimulationOutcome,
}
impl SimulationOffer {
    fn price(&self) -> Result<cost::Price> {
        Ok(match &self.maximum {
            Some(maximum) if self.exact => cost::Price::Exact(maximum.domain()?),
            Some(maximum) => cost::Price::AtMost(maximum.domain()?),
            None => cost::Price::Unknown,
        })
    }
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SimulationRequest {
    /// Explicit dummy identifier. Never published or persisted.
    pub destination: String,
    pub offers: Vec<SimulationOffer>,
    pub budget: Amount,
    pub max_attempts: usize,
    pub order: Order,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct SimulationResponse {
    pub simulated: bool,
    pub outcome: SimulationOutcome,
    pub exposure: Amount,
    pub attempts: usize,
}
/// Uses leaf normalization/transformation and cfbk planning. No credential,
/// transport, database, stateful Contacts or real gate type is accepted.
pub fn simulate(request: SimulationRequest, scope: &[u8], now: u64) -> Result<SimulationResponse> {
    if request.destination.len() > 320
        || request.offers.is_empty()
        || request.offers.len() > 64
        || request.offers.iter().any(|offer| {
            offer.channel.gate() != request.offers[0].channel.gate() || offer.source.len() > 2048
        })
    {
        return Err(Error::Input);
    }
    let budget = request.budget.domain()?;
    let (outcome, exposure, attempts) = if request.offers[0].channel == Channel::Email {
        let offers = request
            .offers
            .iter()
            .map(|offer| {
                Ok(cmbx::SimulationOffer {
                    channel: cmbx::Channel::Email,
                    price: offer.price()?,
                    source: offer.source.clone(),
                    valid_until: offer.valid_until,
                    outcome: offer.outcome.domain(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let result = cmbx::simulate(
            &request.destination,
            scope,
            offers,
            cmbx::SimulationSettings {
                order: request.order.domain(),
                budget,
                max_attempts: request.max_attempts,
                now,
            },
        )
        .map_err(|error| match error {
            cmbx::Error::Budget => Error::Budget,
            _ => Error::Input,
        })?;
        (result.outcome, result.exposure, result.attempts)
    } else {
        let offers = request
            .offers
            .iter()
            .map(|offer| {
                Ok(cphn::SimulationOffer {
                    channel: offer.channel.phone()?,
                    price: offer.price()?,
                    source: offer.source.clone(),
                    valid_until: offer.valid_until,
                    outcome: offer.outcome.domain(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let result = cphn::simulate(
            &request.destination,
            scope,
            offers,
            cphn::SimulationSettings {
                order: request.order.domain(),
                budget,
                max_attempts: request.max_attempts,
                now,
            },
        )
        .map_err(|error| match error {
            cphn::Error::Budget => Error::Budget,
            _ => Error::Input,
        })?;
        (result.outcome, result.exposure, result.attempts)
    };
    Ok(SimulationResponse {
        simulated: true,
        outcome: SimulationOutcome::from_domain(outcome),
        exposure: Amount::from_domain(&exposure),
        attempts,
    })
}
