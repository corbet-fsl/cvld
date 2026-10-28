//! Member account forwarding through the real configured composition.
use super::*;

mod enrollment;
mod settlement;

impl CommunityService {
    pub(crate) fn account_runtime(&self) -> Option<Arc<crate::accounting::clock::AccountRuntime>> {
        self.accounts.clone()
    }
    pub(crate) fn account_shutdown(&self) -> Result<Option<cgts::AccountShutdown>> {
        if self.accounts.is_some() {
            self.facade
                .account_shutdown()
                .map(Some)
                .map_err(Error::Unavailable.redact())
        } else {
            Ok(None)
        }
    }
    pub(crate) fn account_clock(&self) -> Option<Arc<dyn Clock>> {
        self.accounts.as_ref().map(|value| {
            let value: Arc<dyn Clock> = value.clone();
            value
        })
    }
    pub(crate) fn account_body_limit(&self) -> usize {
        self.accounts
            .as_ref()
            .map_or(256 * 1024, |value| value.maximum_request_bytes)
    }
    fn account_time(
        &self,
        runtime: &crate::accounting::clock::AccountRuntime,
        floor: u64,
        until: u64,
    ) -> Result<u64> {
        let now = runtime.observe()?;
        if now < floor || now >= until {
            return Err(Error::Unauthorized);
        }
        Ok(now)
    }
    /// Attach the community-signed Balance publication that names the epoch
    /// descriptor an accepted join-time ancestry sits under. The ledger certifies
    /// that ancestry under its retained anchor, while a newcomer's own
    /// authenticated material may carry no frozen frontier: this publication is
    /// what lets the device check the join-time record leaf. It is the same
    /// publication the community publishes, verified here exactly as the device
    /// verifies it, and attached only when its descriptor names this ancestry's
    /// epoch and root. Nothing is attached otherwise: the acceptance is already
    /// durable and never depends on this evidence. It rides on the answer and on
    /// the authenticated status alike, so a device that lost the answer can still
    /// verify the same acceptance it reads back.
    async fn join_publication(
        &self,
        mut value: cblc::accounting_service::AccountServiceResponse,
        now: u64,
    ) -> cblc::accounting_service::AccountServiceResponse {
        // The ancestry this response carries, when no publication is attached yet.
        let naming = match &value {
            cblc::accounting_service::AccountServiceResponse::ApplyExtended {
                ancestry: Some(ancestry),
                join_publication,
                ..
            } if join_publication.is_none() => Some((ancestry.epoch, ancestry.root)),
            cblc::accounting_service::AccountServiceResponse::Status(status) => status
                .extended
                .as_ref()
                .filter(|evidence| evidence.join_publication.is_none())
                .and_then(|evidence| evidence.ancestry.as_ref())
                .map(|ancestry| (ancestry.epoch, ancestry.root)),
            _ => None,
        };
        let Some((epoch, root)) = naming else {
            return value;
        };
        let policy = self.facade.policy().lock().await;
        let Some(bytes) = policy.balance_publication(now).await.ok().flatten() else {
            return value;
        };
        let material = policy
            .key_ring()
            .ok()
            .and_then(|ring| ring.verify(&bytes, csgn::Kind::SettingsSnapshot, now).ok())
            .and_then(|signed| {
                serde_json::from_slice::<cblc::publication::PublicVerifierMaterial>(
                    signed.payload(),
                )
                .ok()
            })
            .filter(|material| material.validate_at(&self.config.community, now).is_ok());
        if !material
            .and_then(|material| material.record_epoch)
            .is_some_and(|descriptor| descriptor.epoch == epoch && descriptor.root == root)
        {
            return value;
        }
        let publication = cblc::contracts::JoinPublication(bytes);
        match &mut value {
            cblc::accounting_service::AccountServiceResponse::ApplyExtended {
                join_publication,
                ..
            } => *join_publication = Some(publication),
            cblc::accounting_service::AccountServiceResponse::Status(status) => {
                if let Some(evidence) = status.extended.as_mut() {
                    evidence.join_publication = Some(publication);
                }
            }
            _ => {}
        }
        value
    }
    pub(crate) async fn account_credential_issue(
        &mut self,
        bearer: &str,
        request: AccountCredentialRequest,
        proof_time: u64,
    ) -> Result<AccountCredentialResponse> {
        let runtime = self.accounts.clone().ok_or(Error::Unavailable)?;
        if !request.credential.devices.contains(&request.device) {
            return Err(Error::Invalid);
        }
        crate::service::with_live_clock(async {
            let mut now = self.account_time(&runtime, proof_time.max(runtime.floor()), u64::MAX)?;
            let (grant, authentication) = self.authenticate_current(bearer, now).await?;
            now = self.account_time(&runtime, now.max(runtime.floor()), grant.expires)?;
            crate::service::publication::expires_at(grant.expires)?;
            // Capture the exact already-authenticated originating session.
            let session = self.admission_session(&crate::service::Context {
                host: format!("api.{}.{}", self.config.community, self.config.domain),
                grant: Some(grant.clone()),
                token: Some(bearer.into()),
                now,
                authentication: Some(authentication.clone()),
            })?;
            // The proof keeps its original transcript timestamp. Membership
            // authority and every interior legal sample use the live scope.
            let (response, account) = self
                .issue_selected(
                    session,
                    request.credential,
                    None,
                    Some(request.device),
                    proof_time,
                )
                .await?;
            let completed = async {
                now = self.account_time(&runtime, now.max(runtime.floor()), grant.expires)?;
                let (current, auth) = self.authenticate_current(bearer, now).await?;
                self.account_time(&runtime, now.max(runtime.floor()), grant.expires)?;
                if current.session_id != grant.session_id
                    || current.user != grant.user
                    || current.credential != grant.credential
                    || current.expires != grant.expires
                    || current.role != grant.role
                    || !Arc::ptr_eq(&authentication, &auth)
                    || (response.credential.is_some() && account.is_none())
                {
                    return Err(Error::Unauthorized);
                }
                Ok(AccountCredentialResponse {
                    credential: response.credential,
                    lobby: response.lobby,
                    account,
                })
            }
            .await;
            // A complete native/credential decision may already be committed.
            completed.map_err(|_| Error::Reconcile)
        })
        .await
    }

    pub(crate) async fn account(
        &self,
        bearer: &str,
        request: AccountRequest,
        admitted_at: u64,
    ) -> Result<AccountResponse> {
        let runtime = self.accounts.as_ref().ok_or(Error::Unavailable)?;
        let writing = !matches!(
            &request.0,
            cblc::accounting_service::AccountServiceRequest::Status { .. }
                | cblc::accounting_service::AccountServiceRequest::Obligations { .. }
        );
        crate::service::with_live_clock(async {
            let mut now = self.account_time(runtime, admitted_at.max(runtime.floor()), u64::MAX)?;
            let (grant, authentication) = self.authenticate_current(bearer, now).await?;
            now = self.account_time(runtime, now.max(runtime.floor()), grant.expires)?;
            let session = self.sessions.get(bearer).ok_or(Error::Unauthorized)?;
            if !Arc::ptr_eq(&session.authentication, &authentication) {
                return Err(Error::Unauthorized);
            }
            let authority =
                session
                    .authority
                    .lease(session.started, session.grant.expires, runtime.clone());
            self.refresh_global(now).await?;
            now = self.account_time(runtime, now.max(runtime.floor()), grant.expires)?;
            let value = self
                .facade
                .account(authentication.clone(), request.0, now, authority)
                .await
                .map_err(|error| match error {
                    cmty::Error::Reconcile => Error::Reconcile,
                    cmty::Error::AccountUnavailable => Error::Unavailable,
                    // Certain and pre-commit: 409 refused with the reason expired.
                    cmty::Error::AccountExpired => Error::Expired,
                    _ => Error::Refused,
                })?;
            let value = self.join_publication(value, now).await;
            let result = async {
                now = self.account_time(runtime, now.max(runtime.floor()), grant.expires)?;
                let (current, auth) = self.authenticate_current(bearer, now).await?;
                self.account_time(runtime, now.max(runtime.floor()), grant.expires)?;
                if current.session_id != grant.session_id
                    || current.user != grant.user
                    || current.credential != grant.credential
                    || current.expires != grant.expires
                    || current.role != grant.role
                    || !Arc::ptr_eq(&authentication, &auth)
                {
                    return Err(Error::Unauthorized);
                }
                Ok(AccountResponse(value))
            }
            .await;
            result.map_err(|error| if writing { Error::Reconcile } else { error })
        })
        .await
    }
}
