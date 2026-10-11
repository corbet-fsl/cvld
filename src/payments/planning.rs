//! Exact caller terms and inert request-bound previews.
use super::*;
use cpmt::cost::Clock as _;

impl PaymentHost {
    pub fn offer(&self) -> Result<crate::api::PaymentOffer> {
        let offer = self.config.validate(self.clock.now())?;
        if !self.clock.valid() {
            return Err(Error::Expired);
        }
        Ok(crate::api::PaymentOffer {
            option: self.config.id.clone(),
            access: self.config.access.clone(),
            payment_required: crpt::x402::payment_required(&offer).map_err(payment_error)?,
        })
    }
    fn prune(&mut self, now: u64) {
        self.flows.retain(|_, flow| {
            now >= flow.observed && now < flow.until && flow.started.elapsed() < flow.lifetime
        });
    }
    pub fn prepare(
        &mut self,
        context: PreparationContext,
        option: &str,
        payload: Vec<u8>,
        budget: Amount,
    ) -> Result<PaymentPreview> {
        let PreparationContext {
            owner,
            session_expires,
            observed,
            policy,
        } = context;
        let started = Instant::now();
        let now = self.clock.now();
        if !self.clock.valid() || now < observed {
            return Err(Error::Expired);
        }
        self.prune(now);
        if self.flows.len() >= self.config.capacity {
            return Err(Error::Capacity);
        }
        if option != self.config.id || owner.subject.is_empty() {
            return Err(Error::Refused);
        }
        self.config.validate(now)?;
        let requested = budget.domain()?;
        let allowed = self.config.budget.domain()?;
        if requested.unit != allowed.unit || requested.atoms > allowed.atoms {
            return Err(Error::Budget);
        }
        let terms = serde_json::to_vec(&self.config.offer).map_err(|_| Error::Configuration)?;
        if payload.is_empty() || payload.len().saturating_add(terms.len()) > self.config.input_bytes
        {
            return Err(Error::Input);
        }
        let parsed: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| Error::Input)?;
        if !parsed.is_object() {
            return Err(Error::Input);
        }
        let until = now
            .checked_add(self.config.ceremony_seconds)
            .ok_or(Error::Expired)?
            .min(session_expires)
            .min(self.config.tariff.valid_until)
            .min(self.config.access.expires_at);
        if until <= now || until > i64::MAX as u64 {
            return Err(Error::Expired);
        }
        let mut id = [0; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut id);
        let operation = format!(
            "{}{}",
            uuid::Uuid::from_slice(&id[..16])
                .map_err(|_| Error::Input)?
                .simple(),
            uuid::Uuid::from_slice(&id[16..])
                .map_err(|_| Error::Input)?
                .simple()
        );
        let instruction = Instruction {
            kind: cpmt::payments::Action::Execute,
            id,
            parent: None,
            adapter: self.config.provider.clone(),
            operation: "x402.settle".into(),
            binding: Binding {
                scope: self.scope.clone(),
                subject: owner.subject.clone(),
                action: self.action.clone(),
            },
            expires_at: until,
            terms: Private::new(terms),
            evidence: Private::new(payload),
        };
        let quote = self
            .domain
            .preview(
                &instruction,
                self.config.tariff.price(now)?,
                self.config.tariff.source.clone(),
                self.config.tariff.valid_until,
            )
            .map_err(payment_error)?;
        let plan = Self::plan(&instruction, quote.clone(), requested.clone(), now)?;
        if plan.offers().is_empty() {
            return Err(Error::Budget);
        }
        let preview = PaymentPreview {
            operation: operation.clone(),
            authorization: uuid::Uuid::new_v4().to_string(),
            option: self.config.id.clone(),
            access: self.config.access.clone(),
            maximum: Amount::from_domain(quote.price.maximum().ok_or(Error::Budget)?),
            budget,
            exact: self.config.tariff.exact,
            source: self.config.tariff.source.clone(),
            scope: self.config.tariff.scope.clone(),
            expires_at: until,
        };
        self.flows.insert(
            operation,
            Flow {
                owner,
                id: instruction.id,
                binding: instruction.binding.clone(),
                instruction: Some(instruction),
                preview: preview.clone(),
                phase: Phase::Prepared,
                access: None,
                until,
                observed: now,
                started,
                lifetime: Duration::from_secs(until - now),
                policy,
            },
        );
        Ok(preview)
    }
    pub(super) fn plan(
        instruction: &Instruction,
        quote: cost::Quote,
        budget: cost::Amount,
        now: u64,
    ) -> Result<cost::Plan<String, String>> {
        cost::Plan::new(
            vec![cost::Offer {
                candidate: cost::Candidate::new(
                    instruction.adapter.clone(),
                    [instruction.operation.clone()],
                ),
                quote,
            }],
            cost::Config::new(
                [instruction.adapter.clone()],
                [instruction.operation.clone()],
            ),
            cost::CostOrder::Configured,
            budget,
            1,
            cost::Mode::Production,
            now,
        )
        .map_err(|_| Error::Budget)
    }
}
