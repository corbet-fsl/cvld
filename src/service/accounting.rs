//! No operator or caller-selected subject can substitute for member authority.
use super::*;
impl Door {
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
