//! Exact account-owner wire types and maintained owner-generated schemas.
use super::{CredentialRequest, Lobby};
use cblc::accounting_service::{AccountServiceRequest, AccountServiceResponse};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request the original account grant from the same real admission decision.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountCredentialRequest {
    pub credential: CredentialRequest,
    /// Must already be authorized by this original membership.
    pub device: [u8; 32],
}

/// No grant is returned until the actual configured accounting owner and the
/// same complete credential decision have supplied one.
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountCredentialResponse {
    pub credential: Option<Vec<u8>>,
    pub lobby: Lobby,
    pub account: Option<cblc::admission::AdmissionGrant>,
}

/// Transparent original tagged member request. The leaf retains every variant,
/// field, nested bound and strict unknown-field refusal; no local DTO copies.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct AccountRequest(pub AccountServiceRequest);

/// Transparent original owner response, never a host-made acceptance.
#[derive(Serialize, ToSchema)]
#[serde(transparent)]
pub struct AccountResponse(pub AccountServiceResponse);

/// The original signed enrollment request. All account coordinates and
/// signatures are verified by the retained domain owner.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct AccountEnrollmentRequest(pub cblc::enrollment::AccountingDelegation);

/// Registry acknowledgment only; this does not claim an installed checkpoint
/// or an active native account.
#[derive(Serialize, ToSchema)]
#[serde(transparent)]
pub struct AccountEnrollmentResponse(pub cblc::enrollment::EnrollmentEntry);

/// Omit the slot to publish the current roster; a specified slot reads only an
/// already installed historical roster. Neither form grants account authority.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountCheckpointRequest {
    pub slot: Option<u64>,
}

/// Original signed common publication, or absence of that retained slot.
#[derive(Serialize, ToSchema)]
#[serde(transparent)]
pub struct AccountCheckpointResponse(pub Option<cblc::enrollment::EnrollmentPublication>);

/// One anonymous outcome deposit: the Deposit, its native proof and the proof of one
/// unlinkable settlement-pass token. It names no member and must arrive without any
/// member session, over its own circuit; the accounting owner verifies everything and
/// stages the verified facts for the next daily cut.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct SettlementStage(pub cblc::settlement::SettlementSubmission);

/// Durable verified staging (or the original applied effect on an exact replay); never
/// an inbox effect or a published G2 before the daily cut.
#[derive(Serialize)]
#[serde(transparent)]
pub struct SettlementStaged(pub cblc::settlement::SettlementStatus);

/// The owner's canonical schema, projected losslessly (as the accounting crate does for
/// its own request and response), so OpenAPI and MCP show the exact strict wire.
fn owner_schema<T: schemars::JsonSchema>() -> utoipa::openapi::RefOr<utoipa::openapi::Schema> {
    use schemars::{generate::SchemaSettings, transform};
    let schema = SchemaSettings::draft2020_12()
        .with(|settings| {
            settings.meta_schema = None;
            settings.inline_subschemas = true;
        })
        .with_transform(transform::ReplaceConstValue::default())
        .with_transform(transform::ReplaceUnevaluatedProperties::default())
        .into_generator()
        .into_root_schema_for::<T>();
    let value: serde_json::Value = schema.into();
    let projected: utoipa::openapi::RefOr<utoipa::openapi::Schema> =
        serde_json::from_value(value.clone()).expect("owner schema projects to OpenAPI");
    assert_eq!(
        serde_json::to_value(&projected).expect("serializable"),
        value,
        "owner schema projection must be lossless"
    );
    projected
}

impl utoipa::PartialSchema for SettlementStage {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::Schema> {
        owner_schema::<cblc::settlement::SettlementSubmission>()
    }
}
impl ToSchema for SettlementStage {}

impl utoipa::PartialSchema for SettlementStaged {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::Schema> {
        owner_schema::<cblc::settlement::SettlementStatus>()
    }
}
impl ToSchema for SettlementStaged {}
