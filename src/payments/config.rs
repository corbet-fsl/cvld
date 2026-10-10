//! Caller-selected x402 terms, access meaning and all-in service-fee bounds.
use super::{Error, Result};
use cpmt::{access, cost};
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
    pub(crate) fn from_domain(amount: &cost::Amount) -> Self {
        Self {
            unit: amount.unit.code.clone(),
            scale: amount.unit.scale,
            atoms: amount.atoms,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    AllAcceptedRequests,
}

/// Covers discovery, verification and settlement, including failures. This is
/// operator service cost, separate from the principal in the configured offer.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Tariff {
    pub coverage: Coverage,
    pub maximum: Amount,
    pub exact: bool,
    pub source: String,
    pub scope: String,
    pub valid_until: u64,
}
impl Tariff {
    pub(crate) fn price(&self, now: u64) -> Result<cost::Price> {
        text(&self.source, 2048)?;
        text(&self.scope, 2048)?;
        if now >= self.valid_until || self.valid_until > i64::MAX as u64 {
            return Err(Error::Expired);
        }
        let maximum = self.maximum.domain()?;
        Ok(if self.exact {
            cost::Price::Exact(maximum)
        } else {
            cost::Price::AtMost(maximum)
        })
    }
}

/// An exact level and interval selected by the caller. No level ordering, price
/// or subscription period is supplied by this integration.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessTerms {
    pub level: String,
    pub starts_at: u64,
    pub expires_at: u64,
}
impl AccessTerms {
    pub(crate) fn domain(&self) -> Result<access::Request> {
        text(&self.level, 256)?;
        if self.level.contains('/')
            || self.starts_at >= self.expires_at
            || self.expires_at > i64::MAX as u64
        {
            return Err(Error::Configuration);
        }
        Ok(access::Request {
            level: self.level.clone(),
            period: access::Period {
                start: self.starts_at,
                end: self.expires_at,
            },
            requires: cpmt::payments::State::Settled,
        })
    }
}

/// One explicitly enabled account/offer. `provider` identifies this exact
/// account instance in the caller's rulebook, not merely a vendor brand. Account
/// or endpoint changes require a different identity; tokens remain replaceable.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentConfig {
    pub id: String,
    pub provider: String,
    pub gate: String,
    pub account: String,
    pub facilitator_url: String,
    /// Optional file containing an explicit map of authentication header strings.
    pub authentication_file: Option<String>,
    pub journal_key_file: String,
    /// Original maintained x402 v2 offer. Member input cannot replace any term.
    pub offer: serde_json::Value,
    pub access: AccessTerms,
    pub tariff: Tariff,
    pub budget: Amount,
    pub capacity: usize,
    pub ceremony_seconds: u64,
    pub input_bytes: usize,
    pub response_bytes: usize,
    /// Bound for approved serialized opaque operational metadata, not replies.
    pub record_bytes: usize,
    pub transport_timeout_seconds: u64,
}
impl PaymentConfig {
    pub fn validate(&self, now: u64) -> Result<crpt::x402::Offer> {
        for value in [&self.id, &self.provider, &self.account, &self.gate] {
            text(value, 256)?;
        }
        if self.provider.contains('/')
            || self.gate.contains('/')
            || self.capacity == 0
            || self.ceremony_seconds == 0
            || self.transport_timeout_seconds == 0
            || self.input_bytes == 0
            || self.response_bytes == 0
            || self.record_bytes == 0
            || self.ceremony_seconds > i64::MAX as u64
            || std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(self.ceremony_seconds))
                .is_none()
            || std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(
                    self.transport_timeout_seconds,
                ))
                .is_none()
        {
            return Err(Error::Configuration);
        }
        let url = reqwest::Url::parse(&self.facilitator_url).map_err(|_| Error::Configuration)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Configuration);
        }
        self.access.domain()?;
        if now >= self.access.expires_at {
            return Err(Error::Expired);
        }
        let budget = self.budget.domain()?;
        let maximum = self
            .tariff
            .price(now)?
            .maximum()
            .cloned()
            .ok_or(Error::Configuration)?;
        if maximum.unit != budget.unit || maximum.atoms > budget.atoms {
            return Err(Error::Budget);
        }
        let encoded = serde_json::to_vec(&self.offer).map_err(|_| Error::Configuration)?;
        if encoded.len() >= self.input_bytes {
            return Err(Error::Configuration);
        }
        let offer: crpt::x402::Offer =
            serde_json::from_slice(&encoded).map_err(|_| Error::Configuration)?;
        crpt::x402::payment_required(&offer).map_err(|_| Error::Configuration)?;
        Ok(offer)
    }
}

pub(crate) fn text(value: &str, maximum: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(Error::Configuration)
    } else {
        Ok(())
    }
}
