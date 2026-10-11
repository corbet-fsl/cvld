//! Enrollment borrows the same member session and native worker authority.
use super::*;

impl CommunityService {
    pub(crate) async fn account_checkpoint(
        &self,
        request: AccountCheckpointRequest,
        admitted_at: u64,
    ) -> Result<AccountCheckpointResponse> {
        let runtime = self.accounts.as_ref().ok_or(Error::Unavailable)?;
        let publishing = request.slot.is_none();
        crate::service::with_live_clock(async {
            let now = self.account_time(runtime, admitted_at.max(runtime.floor()), u64::MAX)?;
            let clock = runtime.clone();
            let publication = self
                .facade
                .account_checkpoint(request.slot, move || clock.native_time())
                .await
                .map_err(|error| match error {
                    cmty::Error::Reconcile => Error::Reconcile,
                    cmty::Error::AccountUnavailable => Error::Unavailable,
                    _ => Error::Refused,
                })?;
            // A current publication may already be installed. Historical data
            // never renews its original signed interval or a member's grant.
            self.account_time(runtime, now.max(runtime.floor()), u64::MAX)
                .map_err(|error| if publishing { Error::Reconcile } else { error })?;
            Ok(AccountCheckpointResponse(publication))
        })
        .await
    }

    pub(crate) async fn account_enroll(
        &self,
        bearer: &str,
        request: AccountEnrollmentRequest,
        admitted_at: u64,
    ) -> Result<AccountEnrollmentResponse> {
        let runtime = self.accounts.as_ref().ok_or(Error::Unavailable)?;
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
            let entry = self
                .facade
                .enroll_account(authentication.clone(), request.0, now, authority)
                .await
                .map_err(|error| match error {
                    cmty::Error::Reconcile => Error::Reconcile,
                    cmty::Error::AccountUnavailable => Error::Unavailable,
                    _ => Error::Refused,
                })?;
            // The original registry may already have committed. Loss of the
            // exact session after its acknowledgment requires reconciliation.
            let completed = async {
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
                Ok(AccountEnrollmentResponse(entry))
            }
            .await;
            completed.map_err(|_| Error::Reconcile)
        })
        .await
    }
}
