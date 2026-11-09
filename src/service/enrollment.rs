//! Exact member-host routing; no caller-selected identity or operator override.
use super::*;

impl Door {
    pub(crate) async fn global_initial_registration_continue(
        &self,
        ctx: Context,
        request: GlobalInitialRegistrationContinue,
    ) -> Result<InitialCeremony> {
        self.auth(&ctx.host)?
            .lock()
            .await
            .continue_initial_registration(request, ctx.now, self.inner.clock.as_ref())
            .await
    }

    pub(crate) async fn initial_registration_begin(
        &self,
        ctx: Context,
        request: InitialRegistrationBegin,
    ) -> Result<InitialCeremony> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .initial_registration_begin(request, ctx.now)
            .await
    }

    pub(crate) async fn initial_creation(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<InitialCreationResponse> {
        if self.inner.scope == Scope::Global {
            return self
                .auth(&ctx.host)?
                .lock()
                .await
                .initial_creation(
                    ctx.token
                        .as_deref()
                        .ok_or_else(|| crate::refusal::refuse(crate::refusal::Reason::NoToken))?,
                    None,
                    ctx.now,
                    self.inner.clock.as_ref(),
                )
                .await;
        }
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .initial_creation(
                ctx.token
                    .as_deref()
                    .ok_or_else(|| crate::refusal::refuse(crate::refusal::Reason::NoToken))?,
                None,
                ctx.now,
            )
            .await
    }

    pub(crate) async fn initial_publication_bind(
        &self,
        ctx: Context,
        mut request: InitialPublicationBind,
    ) -> Result<InitialCreationResponse> {
        // The nonce binds only this answer to its request; it is never stored or compared.
        let nonce = request.nonce.take();
        let mut response = if self.inner.scope == Scope::Global {
            self.global_initial_publication_bind(ctx, request).await?
        } else {
            if !self.is_community_member(&ctx.host) {
                return Err(Error::WrongHost);
            }
            self.community_backend()?
                .lock()
                .await
                .initial_creation(
                    ctx.token
                        .as_deref()
                        .ok_or_else(|| crate::refusal::refuse(crate::refusal::Reason::NoToken))?,
                    Some(request),
                    ctx.now,
                )
                .await?
        };
        response.nonce = nonce;
        Ok(response)
    }
}

impl Door {
    async fn global_initial_publication_bind(
        &self,
        ctx: Context,
        request: InitialPublicationBind,
    ) -> Result<InitialCreationResponse> {
        // Global sessions are passkey sessions; genesis stamp evidence is community-only. The
        // only evidence accepted here is the wallet's own birth genesis evidence (C4), checked
        // below under the wallet key ring.
        let started = std::time::Instant::now();
        let token = ctx
            .token
            .as_deref()
            .ok_or_else(|| crate::refusal::refuse(crate::refusal::Reason::NoToken))?;
        // Original Auth -> Global lock ordering, as for holder self-ban.
        let authentication = self.auth(&ctx.host)?;
        let mut auth = authentication.lock().await;
        let mut now = self.current_time(&ctx)?;
        let grant = auth.authenticate(token, now).await?;
        if grant.role != Role::Member || auth.operator.is_some() {
            return Err(Error::Forbidden);
        }
        let deadline = started
            .checked_add(std::time::Duration::from_secs(
                grant
                    .expires
                    .checked_sub(ctx.now)
                    .ok_or(Error::Unauthorized)?,
            ))
            .ok_or(Error::Unauthorized)?;
        now = initial_checked_time(self.inner.clock.as_ref(), now, grant.expires, deadline)?;
        let subject =
            cgbl::Subject::new(grant.user.to_string()).map_err(Error::Invalid.redact())?;
        let global = self.global_backend()?.lock().await;
        if let Some(evidence) = request.evidence.as_deref() {
            global.verify_wallet_birth(subject.as_str(), evidence, &request.seed, now)?;
        }
        let eligibility_clock = || self.inner.clock.now();
        now = global
            .facade
            .check_eligibility(&subject, now, &eligibility_clock)
            .await
            .map_err(Error::Refused.redact())?;
        now = initial_checked_time(self.inner.clock.as_ref(), now, grant.expires, deadline)?;
        let state = auth
            .initial_creation(token, Some(request), now, self.inner.clock.as_ref())
            .await?;
        // Already committed: a block, key/session change or stale observation
        // now withholds the reply without pretending the CAS did not happen.
        let result = async {
            let observed = global
                .facade
                .check_eligibility(&subject, state.checked_at, &eligibility_clock)
                .await
                .map_err(Error::Refused.redact())?;
            now = observed;
            let sampled =
                initial_checked_time(self.inner.clock.as_ref(), now, grant.expires, deadline)?;
            let current = auth.authenticate(token, sampled).await?;
            let checked_at =
                initial_checked_time(self.inner.clock.as_ref(), sampled, grant.expires, deadline)?;
            if current.user != grant.user
                || current.session_id != grant.session_id
                || current.credential != grant.credential
                || current.expires != grant.expires
                || checked_at < sampled
                || checked_at >= grant.expires
            {
                return Err(Error::Unauthorized);
            }
            Ok(InitialCreationResponse {
                checked_at,
                ..state
            })
        }
        .await;
        result.map_err(|_| Error::Reconcile)
    }
}

fn initial_checked_time(
    clock: &dyn Clock,
    floor: u64,
    until: u64,
    deadline: std::time::Instant,
) -> Result<u64> {
    let now = clock.now();
    if now < floor || now >= until || std::time::Instant::now() >= deadline {
        return Err(Error::Unauthorized);
    }
    Ok(now)
}
