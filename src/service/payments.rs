//! Paid phases run outside the community lease, with genuine owner rechecks.
use super::*;
use crate::payments::{self, Owner, PolicyBinding};

fn payment_error(error: payments::Error) -> Error {
    match error {
        payments::Error::Input | payments::Error::Configuration => Error::Invalid,
        payments::Error::Capacity => Error::Throttled,
        payments::Error::Storage => Error::Unavailable,
        payments::Error::Uncertain => Error::Reconcile,
        _ => Error::Refused,
    }
}
struct Authority {
    door: Door,
    token: String,
    owner: Owner,
    policy: PolicyBinding,
    until: u64,
    observed: std::sync::atomic::AtomicU64,
}
impl payments::transport::PhaseAuthority for Authority {
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = cpmt::payments::Result<u64>> + Send + '_>>
    {
        Box::pin(async {
            let floor = self.observed.load(std::sync::atomic::Ordering::SeqCst);
            let mut community = self
                .door
                .community_backend()
                .map_err(|_| cpmt::payments::Error::Rejected)?
                .lock()
                .await;
            let authorization = community
                .payment_authorization(
                    &self.token,
                    Some(&self.owner),
                    Some((self.policy.epoch, self.policy.revision)),
                    floor,
                    self.until,
                )
                .await
                .map_err(|_| cpmt::payments::Error::Rejected)?;
            let previous = self
                .observed
                .fetch_max(authorization.observed, std::sync::atomic::Ordering::SeqCst);
            if authorization.observed < previous {
                return Err(cpmt::payments::Error::Expired);
            }
            Ok(authorization.observed)
        })
    }
}
impl Door {
    fn payment_host(&self, ctx: &Context) -> Result<()> {
        if !self.is_community_member(&ctx.host) {
            Err(Error::WrongHost)
        } else {
            Ok(())
        }
    }
    pub(crate) async fn payment_offer(&self, ctx: Context, _: Empty) -> Result<PaymentOffer> {
        self.payment_host(&ctx)?;
        let mut community = self.community_backend()?.lock().await;
        let authorized = community
            .payment_authorization(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                None,
                None,
                ctx.now,
                u64::MAX,
            )
            .await?;
        let payments = community.payments.clone().ok_or(Error::Refused)?;
        drop(community);
        let payments = payments.lock().await;
        payments
            .check_current(authorized.observed, authorized.session_expires)
            .map_err(payment_error)?;
        let offer = payments.offer().map_err(payment_error)?;
        Ok(offer)
    }
    pub(crate) async fn payment_plan(
        &self,
        ctx: Context,
        request: PaymentPlan,
    ) -> Result<PaymentPreview> {
        self.payment_host(&ctx)?;
        let mut community = self.community_backend()?.lock().await;
        let authorization = community
            .payment_authorization(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                None,
                None,
                ctx.now,
                u64::MAX,
            )
            .await?;
        let payments = community.payments.clone().ok_or(Error::Refused)?;
        drop(community);
        let preview = payments
            .lock()
            .await
            .prepare(
                authorization.owner,
                &request.option,
                request.payload,
                request.budget,
                authorization.session_expires,
                authorization.observed,
                PolicyBinding {
                    epoch: authorization.policy_epoch,
                    revision: authorization.policy_revision,
                },
            )
            .map_err(payment_error)?;
        crate::service::publication::expires_at(preview.expires_at)?;
        Ok(preview)
    }
    pub(crate) async fn payment_execute(
        &self,
        ctx: Context,
        request: PaymentExecute,
    ) -> Result<PaymentReceipt> {
        self.payment_host(&ctx)?;
        let token = ctx.token.as_ref().ok_or(Error::Unauthorized)?.clone();
        let (authorization, payments) = {
            let mut community = self.community_backend()?.lock().await;
            (
                community
                    .payment_authorization(&token, None, None, ctx.now, u64::MAX)
                    .await?,
                community.payments.clone().ok_or(Error::Refused)?,
            )
        };
        let mut payments = payments.lock().await;
        let context = payments
            .execution_context(&request.operation, &authorization.owner)
            .map_err(payment_error)?;
        if authorization.policy_epoch != context.policy.epoch
            || authorization.policy_revision != context.policy.revision
        {
            return Err(Error::Refused);
        }
        crate::service::publication::expires_at(context.expires_at)?;
        let authority = Arc::new(Authority {
            door: self.clone(),
            token,
            owner: authorization.owner.clone(),
            policy: context.policy,
            until: context.expires_at,
            observed: std::sync::atomic::AtomicU64::new(
                authorization.observed.max(context.observed),
            ),
        });
        payments
            .execute(
                &request.operation,
                &request.authorization,
                &authorization.owner,
                authority,
            )
            .await
            .map_err(payment_error)
    }
    pub(crate) async fn payment_status(
        &self,
        ctx: Context,
        request: PaymentOperation,
    ) -> Result<PaymentReceipt> {
        self.payment_host(&ctx)?;
        let (authorization, payments) = {
            let mut community = self.community_backend()?.lock().await;
            (
                community
                    .payment_authorization(
                        ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                        None,
                        None,
                        ctx.now,
                        u64::MAX,
                    )
                    .await?,
                community.payments.clone().ok_or(Error::Refused)?,
            )
        };
        let payments = payments.lock().await;
        let receipt = payments
            .status(&request.operation, &authorization.owner)
            .await
            .map_err(payment_error)?;
        let mut community = self.community_backend()?.lock().await;
        let current = community
            .payment_authorization(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                Some(&authorization.owner),
                None,
                authorization.observed,
                authorization.session_expires,
            )
            .await?;
        payments
            .check_current(current.observed, current.session_expires)
            .map_err(payment_error)?;
        Ok(receipt)
    }
    pub(crate) async fn payment_accept(
        &self,
        ctx: Context,
        request: PaymentOperation,
    ) -> Result<PaymentReceipt> {
        self.payment_host(&ctx)?;
        let token = ctx.token.as_ref().ok_or(Error::Unauthorized)?.clone();
        let (authorization, payments) = {
            let mut community = self.community_backend()?.lock().await;
            (
                community
                    .payment_authorization(&token, None, None, ctx.now, u64::MAX)
                    .await?,
                community.payments.clone().ok_or(Error::Refused)?,
            )
        };
        let payments = payments.lock().await;
        let context = payments
            .execution_context(&request.operation, &authorization.owner)
            .map_err(payment_error)?;
        crate::service::publication::expires_at(context.expires_at)?;
        let mut community = self.community_backend()?.lock().await;
        let current = community
            .payment_authorization(
                &token,
                Some(&authorization.owner),
                Some((context.policy.epoch, context.policy.revision)),
                authorization.observed.max(context.observed),
                context.expires_at,
            )
            .await?;
        let now = current.observed;
        let snapshot = community
            .facade
            .snapshot(now)
            .await
            .map_err(Error::Refused.redact())?;
        if snapshot.rules.policy_epoch != context.policy.epoch
            || snapshot.rules.revision != context.policy.revision
        {
            return Err(Error::Refused);
        }
        let config = payments.config();
        let gate = cmty::cgts::payments::PaidAccessGate::new(
            config.gate.clone(),
            config.provider.clone(),
            config.access.level.clone(),
            true,
        )
        .map_err(Error::Invalid.redact())?;
        let checked = community
            .facade
            .gates()
            .run(
                cmty::cgts::Context {
                    snapshot: &snapshot.rules,
                    subject: &authorization.owner.subject,
                    action: cmty::ADMISSION_ACTION,
                    now: now as i64,
                },
                &gate,
                payments
                    .access(&request.operation, &authorization.owner)
                    .map_err(payment_error)?,
            )
            .await
            .map_err(Error::Reconcile.redact())?;
        let retained = checked.result().valid_until;
        let mut receipt = payments
            .status(&request.operation, &authorization.owner)
            .await
            .map_err(payment_error)?;
        let completed = community
            .payment_authorization(
                &token,
                Some(&authorization.owner),
                Some((context.policy.epoch, context.policy.revision)),
                now,
                context.expires_at,
            )
            .await
            .map_err(|_| Error::Reconcile)?;
        payments
            .check_release(&request.operation, &authorization.owner, completed.observed)
            .map_err(|_| Error::Reconcile)?;
        if let Some(access) = receipt.access.as_mut() {
            access.expires_at = u64::try_from(retained).map_err(|_| Error::Reconcile)?;
        }
        Ok(receipt)
    }
    pub(crate) async fn payment_simulate(
        &self,
        ctx: Context,
        request: PaymentSimulationRequest,
    ) -> Result<PaymentSimulationResponse> {
        self.payment_host(&ctx)?;
        payments::simulation::simulate(request, self.current_time(&ctx)?).map_err(payment_error)
    }
}
