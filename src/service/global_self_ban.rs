use super::*;

impl Door {
    pub(crate) async fn global_self_ban_status(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<SelfBanStatus> {
        let token = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
        let authentication = self.auth(&ctx.host)?;
        let mut auth = authentication.lock().await;
        let now = self.current_time(&ctx)?;
        let grant = auth.authenticate(token, now).await?;
        let global = self.global_backend()?.lock().await;
        let observed = self.inner.clock.now();
        if observed < now || observed >= grant.expires {
            return Err(Error::Unauthorized);
        }
        // The genuine wallet login supplies the original enrolment. No member
        // request can name a subject or enumerate other suspension records.
        let self_banned = global
            .facade
            .self_ban_status(
                &cgbl::Subject::new(grant.user.to_string()).map_err(Error::Invalid.redact())?,
            )
            .await
            .map_err(Error::Unavailable.redact())?;
        let now = self.inner.clock.now();
        if now < observed || now >= grant.expires {
            return Err(Error::Unauthorized);
        }
        let current = auth.authenticate(token, now).await?;
        let completed = self.inner.clock.now();
        if current.session_id != grant.session_id
            || current.user != grant.user
            || current.credential != grant.credential
            || completed < now
            || completed >= grant.expires.min(current.expires)
        {
            return Err(Error::Unauthorized);
        }
        Ok(SelfBanStatus { self_banned })
    }

    pub(crate) async fn global_self_ban_begin(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<SelfBanChallenge> {
        self.auth(&ctx.host)?
            .lock()
            .await
            .begin_global_self_ban(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                ctx.now,
                self.inner.clock.as_ref(),
            )
            .await
    }

    pub(crate) async fn global_self_ban_finish(
        &self,
        ctx: Context,
        request: SelfBanConfirmation,
    ) -> Result<Empty> {
        let token = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
        let authentication = self.auth(&ctx.host)?;
        let mut auth = authentication.lock().await;
        let mut session = auth
            .wallet_session(
                token,
                ctx.grant.as_ref().ok_or(Error::Unauthorized)?,
                ctx.now,
                self.inner.clock.as_ref(),
            )
            .await?;
        let mut global = self.global_backend()?.lock().await;
        session
            .check(&mut auth, token, ctx.now, self.inner.clock.as_ref())
            .await?;
        let mutation = global.wallet_mutation().await?;
        if let Some(mutation) = &mutation {
            global
                .signal_wallet_mutation(&session, mutation, self.inner.clock.as_ref())
                .await?;
        }
        let confirmed = auth
            .finish_global_self_ban_wallet(
                token,
                request,
                session.checked_at()?,
                self.inner.clock.as_ref(),
                mutation,
            )
            .await?;
        let now = self.current_time(&ctx)?;
        let grant = auth.authenticate(token, now).await?;
        let now = confirmed.validate(&grant, now, self.inner.clock.as_ref())?;
        global
            .facade
            .suspend(
                &cgbl::Subject::new(confirmed.user().to_string())
                    .map_err(Error::Invalid.redact())?,
                cgbl::Suspension::Permanent(cgbl::PermanentReason::SelfBan),
                now,
            )
            .await
            .map_err(Error::Reconcile.redact())?;
        auth.logout_account(confirmed.user());
        // Suspension has committed even if publishing the advanced epoch fails.
        global.publish_wallet(self.inner.clock.now()).await?;
        global
            .refresh(self.inner.clock.now())
            .await
            .map_err(Error::Reconcile.redact())?;
        Ok(Empty {})
    }
}
