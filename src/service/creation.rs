//! Self-service community creation: token issuance and creation at the global
//! door (through the hosting hub) and the creator's claim at the community door.
use super::*;
use crate::{
    api::{
        AddressAnswer, AddressCheck, CommunityCreate, CommunityCreated, CommunityTerminate, CommunityTerms,
        CommunityTermsRequest, CreationClaim, CreationClaimed, CreationTokenKey,
        CreationTokenRequest, CreationTokenResponse, Empty,
    },
    hosts::Boxed,
};

/// What the global door needs from the process that hosts communities. The hub
/// owns the registry, the token issuer, host provisioning and the community
/// doors; the door itself keeps no state about them.
pub trait CommunityHub: Send + Sync {
    /// Verify the token, register the shell, open and provision the community,
    /// and return the creator's claim. Rolls everything back on any failure.
    fn create<'a>(
        &'a self,
        request: CommunityCreate,
        now: u64,
    ) -> Boxed<'a, Result<CommunityCreated>>;
    /// What a device must prove before it creates a community at this address.
    fn terms<'a>(
        &'a self,
        request: CommunityTermsRequest,
        now: u64,
    ) -> Boxed<'a, Result<CommunityTerms>>;
    /// Whether an address is usable and free, with a length light and suggestions.
    fn address<'a>(&'a self, request: AddressCheck, now: u64)
    -> Boxed<'a, Result<AddressAnswer>>;
    /// Count one issuance for this person and blind-sign the request.
    fn issue_token<'a>(
        &'a self,
        subject: &'a str,
        blinded: &'a [u8],
        now: u64,
    ) -> Boxed<'a, Result<Vec<u8>>>;
    /// Root ends a community; see `Hub::end`.
    fn terminate<'a>(&'a self, request: CommunityTerminate, now: u64) -> Boxed<'a, Result<()>>;
    /// The public key that verifies creation tokens (DER).
    fn token_key(&self) -> Result<Vec<u8>>;
    /// True when `host` resolves to a LIVE community of this hub (unknown, shell, ending and
    /// ended hosts are all false); the OHTTP gateway serves exactly these authorities.
    fn serves_host<'a>(&'a self, _host: &'a str) -> Boxed<'a, bool> {
        Box::pin(async { false })
    }
}

/// Where the hub states that a community's key chain ended: the platform feed.
pub trait EndFeed: Send + Sync {
    /// Publish one end-of-chain statement. Idempotent per fingerprint.
    fn publish<'a>(&'a self, entry: cmty::cplc::EndedChain, now: u64) -> Boxed<'a, Result<()>>;
}

impl EndFeed for Door {
    fn publish<'a>(&'a self, entry: cmty::cplc::EndedChain, now: u64) -> Boxed<'a, Result<()>> {
        Box::pin(async move {
            let mut global = self.global_backend()?.lock().await;
            let wallet = global.wallet.as_mut().ok_or(Error::Forbidden)?;
            wallet
                .end_chain(entry, now)
                .await
                .map_err(Error::Unavailable.redact())
        })
    }
}

impl Door {
    /// Attach the hosting hub to a global door. Done once, by the launcher.
    pub fn attach_hub(&self, hub: Arc<dyn CommunityHub>) -> Result<()> {
        if self.inner.scope != Scope::Global {
            return Err(Error::WrongHost);
        }
        self.inner.hub.set(hub).map_err(|_| Error::Forbidden)
    }
    fn hub(&self) -> Result<&Arc<dyn CommunityHub>> {
        if self.inner.scope != Scope::Global {
            return Err(Error::WrongHost);
        }
        self.inner.hub.get().ok_or(Error::Unavailable)
    }
    pub(crate) async fn creation_token_key(
        &self,
        _ctx: Context,
        _request: Empty,
    ) -> Result<CreationTokenKey> {
        Ok(CreationTokenKey {
            public_key: self.hub()?.token_key()?,
        })
    }
    pub(crate) async fn creation_token_issue(
        &self,
        ctx: Context,
        request: CreationTokenRequest,
    ) -> Result<CreationTokenResponse> {
        let subject = ctx.subject()?;
        let blind_signature = self
            .hub()?
            .issue_token(subject.as_str(), &request.blinded, ctx.now)
            .await?;
        Ok(CreationTokenResponse { blind_signature })
    }
    pub(crate) async fn community_create(
        &self,
        ctx: Context,
        request: CommunityCreate,
    ) -> Result<CommunityCreated> {
        self.hub()?.create(request, ctx.now).await
    }
    pub(crate) async fn address_check(
        &self,
        ctx: Context,
        request: AddressCheck,
    ) -> Result<AddressAnswer> {
        self.hub()?.address(request, ctx.now).await
    }
    pub(crate) async fn community_terms(
        &self,
        ctx: Context,
        request: CommunityTermsRequest,
    ) -> Result<CommunityTerms> {
        self.hub()?.terms(request, ctx.now).await
    }
    pub(crate) async fn community_terminate(
        &self,
        ctx: Context,
        request: CommunityTerminate,
    ) -> Result<Empty> {
        self.hub()?.terminate(request, ctx.now).await?;
        Ok(Empty {})
    }
    pub(crate) async fn community_dissolve(&self, ctx: Context, _request: Empty) -> Result<Empty> {
        let lifecycle = self.community_backend()?.lock().await.lifecycle()?;
        lifecycle.dissolve(ctx.now).await?;
        Ok(Empty {})
    }
    pub(crate) async fn community_creation_claim(
        &self,
        ctx: Context,
        request: CreationClaim,
    ) -> Result<CreationClaimed> {
        with_live_clock(
            self.community_backend()?
                .lock()
                .await
                .creation_claim(&ctx, request),
        )
        .await
    }
}

impl Door {
    /// Hub only: arm a community that is being created with its claim gate.
    pub(crate) async fn attach_creation_gate(
        &self,
        gate: Arc<dyn crate::community::creation::CreationGate>,
    ) -> Result<()> {
        self.community_backend()?
            .lock()
            .await
            .set_creation_gate(gate);
        Ok(())
    }
    /// Hub only: whether the creator has been admitted as first admin.
    pub(crate) async fn community_active(&self) -> Result<bool> {
        self.community_backend()?
            .lock()
            .await
            .creation_active()
            .await
    }
    /// The founding (genesis) document of a community created after genesis existed.
    pub async fn community_genesis(&self) -> Result<Vec<u8>> {
        self.community_backend()?
            .lock()
            .await
            .genesis()
            .await?
            .ok_or(Error::Unavailable)
    }
}

impl Door {
    /// Launcher only: arm a one-time creator claim for a statically configured
    /// community that is created without the hub. The secret is kept only as a
    /// hash; the claim expires at `valid_until`.
    pub async fn arm_creation(&self, secret: &[u8], valid_until: u64) -> Result<()> {
        if secret.len() < 16 {
            return Err(Error::Invalid);
        }
        self.attach_creation_gate(Arc::new(crate::community::creation::StaticGate {
            hash: crate::community::creation::StaticGate::hash(secret),
            valid_until,
        }))
        .await
    }
}

impl Door {
    /// Hub only: let this community's admins dissolve it.
    pub(crate) async fn attach_lifecycle(
        &self,
        lifecycle: Arc<dyn crate::community::creation::Lifecycle>,
    ) -> Result<()> {
        self.community_backend()?
            .lock()
            .await
            .set_lifecycle(lifecycle);
        Ok(())
    }
}
