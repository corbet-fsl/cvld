//! Original enrollment provenance; no root, signing or ordinary use capability.
use super::*;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

impl CommunityService {
    pub async fn initial_registration_begin(
        &mut self,
        request: InitialRegistrationBegin,
        now: u64,
    ) -> Result<Ceremony> {
        self.register_begin_for(
            RegisterStart {
                bootstrap: None,
                passport: Some(request.passport),
            },
            Some(request.seed),
            now,
        )
        .await
    }

    pub async fn initial_creation(
        &self,
        bearer: &str,
        bind: Option<InitialPublicationBind>,
        admitted_at: u64,
    ) -> Result<InitialCreationResponse> {
        crate::service::with_live_clock(async {
            let mut now = self.initial_time(admitted_at, u64::MAX)?;
            let (grant, authentication) = self.authenticate_current(bearer, now).await?;
            now = self.initial_time(now, grant.expires)?;
            // Preserve Policy -> Member ordering and retain both owners through
            // the final synchronous output check. No member-lock re-entry below.
            let mut policy = self.facade.policy().lock().await;
            now = self.initial_time(now, grant.expires)?;
            let snapshot = policy
                .verified_settings(now)
                .await
                .map_err(Error::Refused.redact())?;
            let until = grant.expires.min(snapshot.valid_until());
            crate::service::publication::expires_at(until)?;
            now = self.initial_time(now, until)?;
            let expires_at = until.try_into().map_err(Error::Unauthorized.redact())?;
            let writing = bind.is_some();
            let mut state = match bind {
                Some(bind) => {
                    self.facade
                        .membership()
                        .bind_initial_publication(
                            &authentication,
                            bind.seed,
                            bind.publication,
                            expires_at,
                        )
                        .await
                }
                None => {
                    self.facade
                        .membership()
                        .initial_creation(&authentication, expires_at)
                        .await
                }
            }
            .map_err(|error| {
                if writing && error == cmbr::Error::Unavailable {
                    Error::Reconcile
                } else {
                    Error::Refused
                }
            })?;
            // A bind may already be durable. Any subsequent failed check only
            // withholds the receipt; it cannot establish that no write occurred.
            let result = async {
                now = self.initial_time(now.max(initial_floor(state.observed_at())?), until)?;
                if !state.is_current(now.try_into().map_err(Error::Unauthorized.redact())?) {
                    return Err(Error::Unauthorized);
                }
                let completed = self
                    .facade
                    .membership()
                    .check_initial_creation(&mut state)
                    .await
                    .map_err(Error::Refused.redact())?;
                now = self.initial_time(
                    now.max(initial_floor(completed)?)
                        .max(initial_floor(state.observed_at())?),
                    until,
                )?;
                let current = self.sessions.get(bearer).ok_or(Error::Unauthorized)?;
                if current.grant.session_id != grant.session_id
                    || current.grant.user != grant.user
                    || current.grant.credential != grant.credential
                    || current.grant.expires != grant.expires
                    || current.grant.role != grant.role
                    || !Arc::ptr_eq(&current.authentication, &authentication)
                    || !state.is_current(now.try_into().map_err(Error::Unauthorized.redact())?)
                {
                    return Err(Error::Unauthorized);
                }
                Ok(InitialCreationResponse {
                    seed: state.seed(),
                    publication: state.publication(),
                    checked_at: now,
                })
            }
            .await;
            drop(state);
            drop(policy);
            result.map_err(|error| if writing { Error::Reconcile } else { error })
        })
        .await
    }

    fn initial_time(&self, floor: u64, until: u64) -> Result<u64> {
        let now = self.clock.now();
        if now < floor || now >= until || i64::try_from(now).is_err() {
            return Err(Error::Unauthorized);
        }
        Ok(now)
    }
}

fn initial_floor(now: i64) -> Result<u64> {
    now.try_into().map_err(Error::Unauthorized.redact())
}
