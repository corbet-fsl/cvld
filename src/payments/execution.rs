//! Single-use execution and genuine paid-access release.
use super::*;
use cpmt::cost::Clock as _;
#[cfg(test)]
#[path = "tests/lifetimes.rs"]
mod tests;

impl PaymentHost {
    pub fn check_current(&self, observed: u64, until: u64) -> Result<u64> {
        let now = self.clock.now();
        if !self.clock.valid() || now < observed || now >= until {
            return Err(Error::Expired);
        }
        Ok(now)
    }
    pub fn check_release(&self, operation: &str, owner: &Owner, observed: u64) -> Result<u64> {
        let flow = self.flow(operation, owner)?;
        let now = Self::current(self.clock.as_ref(), flow)?;
        if now < observed {
            return Err(Error::Expired);
        }
        Ok(now)
    }
    fn flow(&self, operation: &str, owner: &Owner) -> Result<&Flow> {
        let flow = self.flows.get(operation).ok_or(Error::Refused)?;
        if &flow.owner != owner {
            return Err(Error::Refused);
        }
        Ok(flow)
    }
    pub fn execution_context(&self, operation: &str, owner: &Owner) -> Result<ExecutionContext> {
        let flow = self.flow(operation, owner)?;
        let observed = Self::current(self.clock.as_ref(), flow)?;
        Ok(ExecutionContext {
            policy: flow.policy,
            expires_at: flow.until,
            observed,
        })
    }
    fn current(clock: &ObservedClock, flow: &Flow) -> Result<u64> {
        let now = clock.now();
        if !clock.valid()
            || now < flow.observed
            || now >= flow.until
            || flow.started.elapsed() >= flow.lifetime
        {
            return Err(Error::Expired);
        }
        Ok(now)
    }
    pub async fn execute(
        &mut self,
        operation: &str,
        authorization: &str,
        owner: &Owner,
        authority: Arc<dyn transport::PhaseAuthority>,
    ) -> Result<PaymentReceipt> {
        let flow = self.flows.get_mut(operation).ok_or(Error::Refused)?;
        if &flow.owner != owner || flow.preview.authorization != authorization {
            return Err(Error::Refused);
        }
        if !matches!(flow.phase, Phase::Prepared) {
            return Err(Error::Conflict);
        }
        let now = Self::current(self.clock.as_ref(), flow)?;
        let observed = authority.check().await.map_err(payment_error)?;
        if observed < now {
            return Err(Error::Expired);
        }
        flow.observed = observed;
        let now = Self::current(self.clock.as_ref(), flow)?;
        let quote = self
            .domain
            .preview(
                flow.instruction.as_ref().ok_or(Error::Conflict)?,
                self.config.tariff.price(now)?,
                self.config.tariff.source.clone(),
                self.config.tariff.valid_until,
            )
            .map_err(payment_error)?;
        let mut cascade = Self::plan(
            flow.instruction.as_ref().ok_or(Error::Conflict)?,
            quote,
            flow.preview.budget.domain()?,
            now,
        )?
        .start();
        let permit = cascade.begin(now).map_err(|_| Error::Budget)?;
        let _lease = self
            .phase_transport
            .begin(
                authority.clone(),
                now,
                flow.until,
                flow.started,
                flow.lifetime,
                self.clock.clone(),
            )
            .map_err(payment_error)?;
        // Cancellation from this point leaves RAM Running and durable Unknown;
        // neither exact retry nor a lost pending response resends settlement.
        let instruction = flow.instruction.take().ok_or(Error::Conflict)?;
        flow.phase = Phase::Running;
        let result = self.domain.dispatch(&instruction, permit, now).await;
        let execution = match result {
            Ok(execution) => execution,
            Err(_) => {
                let receipt = PaymentReceipt {
                    operation: operation.into(),
                    outcome: PaymentOutcome::Uncertain,
                    access: None,
                };
                flow.phase = Phase::Finished(receipt.clone());
                return Ok(receipt);
            }
        };
        let phase_floor = self
            .phase_transport
            .observed()
            .map_err(|_| Error::Uncertain)?;
        let final_observed = authority.check().await.map_err(|_| Error::Uncertain)?;
        if final_observed < flow.observed || final_observed < phase_floor {
            return Err(Error::Uncertain);
        }
        flow.observed = final_observed;
        let now = Self::current(self.clock.as_ref(), flow).map_err(|_| Error::Uncertain)?;
        let outcome = if execution.commit_error.is_some() || execution.cost.violation.is_some() {
            PaymentOutcome::Uncertain
        } else {
            match execution.outcome.state() {
                State::Settled if execution.outcome.satisfies_terms() => PaymentOutcome::Settled,
                State::Unknown => PaymentOutcome::Uncertain,
                State::Pending | State::RequiresAction => PaymentOutcome::Pending,
                _ => PaymentOutcome::Refused,
            }
        };
        if outcome == PaymentOutcome::Settled {
            flow.access = Some(
                self.domain
                    .paid_access(
                        &instruction,
                        &execution.outcome,
                        self.config.access.domain()?,
                        now,
                    )
                    .map_err(payment_error)?,
            );
        }
        // Financial/provider results and member_action are dropped inside this
        // integration; only exact requested level/period leaves the boundary.
        let receipt = PaymentReceipt {
            operation: operation.into(),
            outcome,
            access: flow.access.as_ref().and_then(|access| {
                access
                    .in_context(&flow.binding, now)
                    .ok()
                    .map(|(level, period)| AccessTerms {
                        level: level.into(),
                        starts_at: period.start,
                        expires_at: period.end,
                    })
            }),
        };
        flow.phase = Phase::Finished(receipt.clone());
        Ok(receipt)
    }
    pub async fn status(&self, operation: &str, owner: &Owner) -> Result<PaymentReceipt> {
        let Some(flow) = self.flows.get(operation) else {
            // Fresh genuine own-member authentication belongs to the host.
            // Original RAM terms lost on restart never mint access authority.
            if operation.len() != 64 {
                return Err(Error::Input);
            }
            let first = uuid::Uuid::parse_str(operation.get(..32).ok_or(Error::Input)?)
                .map_err(|_| Error::Input)?;
            let second = uuid::Uuid::parse_str(operation.get(32..).ok_or(Error::Input)?)
                .map_err(|_| Error::Input)?;
            let mut id = [0; 32];
            id[..16].copy_from_slice(first.as_bytes());
            id[16..].copy_from_slice(second.as_bytes());
            let binding = Binding {
                scope: self.scope.clone(),
                subject: owner.subject.clone(),
                action: self.action.clone(),
            };
            let outcome = self
                .domain
                .outcome(&id, &binding)
                .await
                .map_err(payment_error)?;
            let outcome = match outcome.state() {
                State::Settled if outcome.satisfies_terms() => PaymentOutcome::Settled,
                State::Pending | State::RequiresAction => PaymentOutcome::Pending,
                State::Unknown => PaymentOutcome::Uncertain,
                _ => PaymentOutcome::Refused,
            };
            return Ok(PaymentReceipt {
                operation: operation.into(),
                outcome,
                access: None,
            });
        };
        if &flow.owner != owner {
            return Err(Error::Refused);
        }
        Ok(match &flow.phase {
            Phase::Prepared => PaymentReceipt {
                operation: operation.into(),
                outcome: PaymentOutcome::Prepared,
                access: None,
            },
            Phase::Finished(receipt) => receipt.clone(),
            Phase::Running => {
                let _ = self.domain.outcome(&flow.id, &flow.binding).await;
                PaymentReceipt {
                    operation: operation.into(),
                    outcome: PaymentOutcome::Uncertain,
                    access: None,
                }
            }
        })
    }
    /// Genuine in-process paid-access only; member DTOs cannot create this fact.
    pub fn access(&self, operation: &str, owner: &Owner) -> Result<&access::PaidAccess> {
        let flow = self.flow(operation, owner)?;
        let now = Self::current(self.clock.as_ref(), flow)?;
        let access = flow.access.as_ref().ok_or(Error::Refused)?;
        access
            .in_context(&flow.binding, now)
            .map_err(payment_error)?;
        Ok(access)
    }
}
