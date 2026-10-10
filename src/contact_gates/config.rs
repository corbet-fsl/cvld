//! Explicit provider configuration and integer cost projections. No price discovery.
use super::{Error, Result};
use cfbk::cost;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Amount {
    pub unit: String,
    pub scale: u8,
    pub atoms: u64,
}
impl Amount {
    pub(crate) fn domain(&self) -> Result<cost::Amount> {
        if self.unit.is_empty()
            || self.unit.len() > 64
            || !self.unit.bytes().all(|b| b.is_ascii_graphic())
            || self.scale > 18
            || self.atoms > i64::MAX as u64
        {
            return Err(Error::Configuration);
        }
        Ok(cost::Amount {
            unit: cost::Unit {
                code: self.unit.clone(),
                scale: self.scale,
            },
            atoms: self.atoms,
        })
    }
    pub(crate) fn from_domain(value: &cost::Amount) -> Self {
        Self {
            unit: value.unit.code.clone(),
            scale: value.unit.scale,
            atoms: value.atoms,
        }
    }
}

/// The operator vouches for this all-in bound for the configured operation,
/// including failed attempts and provider-managed delivery changes. Scope is a
/// required description of the account/service/channel/request conditions under
/// which it is valid, not a claim that this library discovered current prices.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Tariff {
    /// This integration accepts only an all-in bound covering every request
    /// accepted through the configured account/service/channel/operation.
    pub coverage: Coverage,
    pub maximum: Amount,
    pub exact: bool,
    pub source: String,
    pub scope: String,
    pub valid_until: u64,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    AllAcceptedRequests,
}
impl Tariff {
    pub(crate) fn price(&self, now: u64) -> Result<cost::Price> {
        if self.source.is_empty()
            || self.source.len() > 2048
            || self.scope.is_empty()
            || self.scope.len() > 2048
            || self.valid_until <= now
            || self.valid_until > i64::MAX as u64
        {
            return Err(Error::Configuration);
        }
        let value = self.maximum.domain()?;
        Ok(if self.exact {
            cost::Price::Exact(value)
        } else {
            cost::Price::AtMost(value)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Sms,
    Whatsapp,
    Call,
    Email,
}
impl Channel {
    pub fn gate(self) -> &'static str {
        if self == Self::Email { "cmbx" } else { "cphn" }
    }
    pub(crate) fn phone(self) -> Result<cphn::Channel> {
        match self {
            Self::Sms => Ok(cphn::Channel::Sms),
            Self::Whatsapp => Ok(cphn::Channel::Whatsapp),
            Self::Call => Ok(cphn::Channel::Call),
            Self::Email => Err(Error::Configuration),
        }
    }
}

/// A configured option is enabled only by inclusion in the caller's selected
/// list. Credentials and the stable comparison key are distinct supplied files.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub id: String,
    pub provider: String,
    pub account: String,
    pub service: String,
    pub credential_file: String,
    pub channel: Channel,
    pub begin: Tariff,
    pub check: Tariff,
}

/// No provider or tariff defaults are supplied.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContactConfig {
    pub providers: Vec<ProviderConfig>,
    pub phone_identity_key_file: Option<String>,
    pub mailbox_identity_key_file: Option<String>,
    pub capacity: usize,
    pub ceremony_seconds: u64,
    /// Operator-authorized upper bound for one whole begin/fallback/check flow.
    pub budget: Amount,
    pub max_attempts: usize,
    pub transport_timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Order {
    Configured,
    Cheapest,
}
impl Order {
    pub(crate) fn domain(self) -> cost::CostOrder {
        match self {
            Self::Configured => cost::CostOrder::Configured,
            Self::Cheapest => cost::CostOrder::Cheapest,
        }
    }
}
