//! No operator or caller-selected subject can substitute for member authority.
use super::*;
impl Door {
    pub(crate) async fn account_checkpoint(
        &self,
        ctx: Context,
        request: AccountCheckpointRequest,
    ) -> Result<AccountCheckpointResponse> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .account_checkpoint(request, ctx.now)
            .await
    }

    /// Anonymous ingress: a request that carries any session token is refused, because
    /// the session would link the outcome to the member who deposits it.
    pub(crate) async fn account_settlement_stage(
        &self,
        ctx: Context,
        request: SettlementStage,
    ) -> Result<SettlementStaged> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        if ctx.token.is_some() {
            return Err(Error::Unauthorized);
        }
        self.community_backend()?
            .lock()
            .await
            .account_settlement_stage(request, ctx.now)
            .await
    }

    pub(crate) async fn account_enroll(
        &self,
        ctx: Context,
        request: AccountEnrollmentRequest,
    ) -> Result<AccountEnrollmentResponse> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .account_enroll(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                request,
                ctx.now,
            )
            .await
    }

    pub(crate) async fn account_credential_issue(
        &self,
        ctx: Context,
        request: AccountCredentialRequest,
    ) -> Result<AccountCredentialResponse> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .account_credential_issue(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                request,
                ctx.now,
            )
            .await
    }
    pub(crate) async fn account(
        &self,
        ctx: Context,
        request: AccountRequest,
    ) -> Result<AccountResponse> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .account(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                request,
                ctx.now,
            )
            .await
    }
}
