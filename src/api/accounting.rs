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
