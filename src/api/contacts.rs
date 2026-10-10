use super::*;
pub use crate::contact_gates::simulation::{
    SimulationRequest as ContactSimulationRequest, SimulationResponse as ContactSimulationResponse,
};
use crate::contact_gates::{Amount, Order};
pub use crate::contact_gates::{Preview as ContactPreview, Receipt as ContactReceipt};

/// Selected configured options and a caller budget. Provider credentials,
/// policy scope, original check and evidence lifetime are host-owned.
#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContactPlan {
    pub options: Vec<String>,
    pub destination: String,
    pub budget: Amount,
    pub max_attempts: usize,
    pub order: Order,
}
#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContactOperation {
    pub operation: String,
}
#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContactExecute {
    pub operation: String,
    pub authorization: String,
}
#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContactCheck {
    pub operation: String,
    pub code: String,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContactAcceptance {
    pub gate: String,
    pub provider: String,
    pub valid_until: u64,
}
