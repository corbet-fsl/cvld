//! Minimal paid-access negotiation and exact operation consent.
use super::*;
pub use crate::payments::simulation::{
    SimulationRequest as PaymentSimulationRequest, SimulationResponse as PaymentSimulationResponse,
};
pub use crate::payments::{AccessTerms, Amount, PaymentOutcome, PaymentPreview, PaymentReceipt};

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentPlan {
    pub option: String,
    /// Hostile original x402 payment payload. No authenticated fact is accepted.
    pub payload: Vec<u8>,
    /// Member can lower only the configured operator service-fee budget.
    pub budget: Amount,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentExecute {
    pub operation: String,
    pub authorization: String,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentOperation {
    pub operation: String,
}

/// The original x402 offer must be presented before the member signs it. It is
/// supplied by caller policy, never inferred from a member payload or vendor.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentOffer {
    pub option: String,
    pub access: AccessTerms,
    pub payment_required: String,
}
