//! Exact member-host routing; no caller-selected identity or operator override.
use super::*;

impl Door {
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
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .initial_creation(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                None,
                ctx.now,
            )
            .await
    }

    pub(crate) async fn initial_publication_bind(
        &self,
        ctx: Context,
        request: InitialPublicationBind,
    ) -> Result<InitialCreationResponse> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .initial_creation(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                Some(request),
                ctx.now,
            )
            .await
    }
}
