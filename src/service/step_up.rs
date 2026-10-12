//! Fresh-assertion step-up for account-authority actions.
use super::*;

impl Door {
    pub(crate) async fn step_up_begin(
        &self,
        ctx: Context,
        request: StepUpStart,
    ) -> Result<StepUpChallenge> {
        let grant = ctx.grant.as_ref().ok_or(Error::Unauthorized)?;
        if self.is_membership_host(&ctx.host) {
            return self
                .community_backend()?
                .lock()
                .await
                .step_up_begin(ctx.member()?, grant, &ctx.host, request.action, ctx.now)
                .await;
        }
        self.auth(&ctx.host)?
            .lock()
            .await
            .step_up_begin(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                &ctx.host,
                request.action,
                ctx.now,
                self.inner.clock.as_ref(),
            )
            .await
    }

    /// Consume one fresh user-verifying assertion for exactly this action. Root
    /// sessions need none: the Root portal sign-in is their step-up.
    pub(crate) async fn require_step_up(
        &self,
        ctx: &Context,
        action: StepUpAction,
        proof: Option<StepUpProof>,
    ) -> Result<()> {
        let grant = ctx.grant.as_ref().ok_or(Error::Unauthorized)?;
        if grant.role == Role::Root {
            return Ok(());
        }
        let proof = proof.ok_or(Error::Forbidden)?;
        if self.is_membership_host(&ctx.host) {
            return self
                .community_backend()?
                .lock()
                .await
                .step_up_consume(ctx.member()?, grant, &ctx.host, &action, proof, ctx.now)
                .await;
        }
        let token = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
        let clock = self.inner.clock.as_ref();
        let authentication = self.auth(&ctx.host)?;
        let mut auth = authentication.lock().await;
        if self.service_scope() != Scope::Global || grant.role != Role::Member {
            return auth
                .step_up_consume(token, &ctx.host, &action, proof, ctx.now, clock, None)
                .await;
        }
        // The wallet's passkey counters change only under its mutation owner.
        let mut session = auth.wallet_session(token, grant, ctx.now, clock).await?;
        let mut global = self.global_backend()?.lock().await;
        session.check(&mut auth, token, ctx.now, clock).await?;
        let mutation = global.wallet_mutation().await?;
        if let Some(mutation) = &mutation {
            global
                .signal_wallet_mutation(&session, mutation, clock)
                .await?;
        }
        auth.step_up_consume(
            token,
            &ctx.host,
            &action,
            proof,
            session.checked_at()?,
            clock,
            mutation,
        )
        .await
    }
}
