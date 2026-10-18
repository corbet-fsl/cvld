//! Trusted in-process linkage; no member-selected signer or remote role token.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One root-scoped purpose issuer shared by explicitly linked source hosts.
/// Its key is private, never serialized or supplied in source configuration.
pub struct RootBoardPurpose {
    pub(crate) issuer: crate::community::root_issuance::Issuer,
    pub(crate) domain: String,
    clock: Arc<dyn Clock>,
    observed: AtomicU64,
    invalid: AtomicBool,
}

impl RootBoardPurpose {
    pub(crate) fn now(&self) -> Result<u64> {
        let now = self.clock.now();
        if now == 0 || now < self.observed.fetch_max(now, Ordering::SeqCst) {
            self.invalid.store(true, Ordering::SeqCst);
        }
        if self.invalid.load(Ordering::SeqCst) {
            Err(Error::Unavailable)
        } else {
            Ok(now)
        }
    }
}

impl Door {
    /// Provision only this actual root host's dedicated purpose signer. The
    /// caller owns secret-file loading; this operation has no HTTP/MCP action.
    pub async fn root_board_purpose(&self, key: cpsd::IssuerKey) -> Result<Arc<RootBoardPurpose>> {
        let community = self.community_backend()?.lock().await;
        if !community.is_root_board() {
            return Err(Error::WrongHost);
        }
        let now = self.inner.clock.now();
        let issuer = community
            .facade
            .root_board_issuer(key, now)
            .await
            .map_err(Error::Unavailable.redact())?;
        let purpose = Arc::new(RootBoardPurpose {
            issuer,
            domain: community.config.domain.clone(),
            clock: self.inner.clock.clone(),
            observed: AtomicU64::new(now),
            invalid: AtomicBool::new(false),
        });
        purpose.now()?;
        Ok(purpose)
    }

    /// Attach the shared opaque ROOT owner once to this explicit source host.
    /// No ordinary source configuration contains the common private key.
    pub async fn attach_root_board_purpose(&self, purpose: Arc<RootBoardPurpose>) -> Result<()> {
        let mut community = self.community_backend()?.lock().await;
        if community.is_root_board()
            || community.config.domain != purpose.domain
            || community.root_purpose.is_some()
        {
            return Err(Error::Invalid);
        }
        purpose.now()?;
        community.root_purpose = Some(purpose);
        Ok(())
    }

    pub(crate) async fn root_board_issue_begin(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<RootBoardIssueChallenge> {
        if !self.is_garden(&ctx.host) {
            return Err(Error::WrongHost);
        }
        let bearer = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
        let mut community = self.community_backend()?.lock().await;
        with_live_clock(community.begin_root_issuance(bearer, ctx.now)).await
    }

    pub(crate) async fn root_board_issue_finish(
        &self,
        ctx: Context,
        request: RootBoardIssueFinish,
    ) -> Result<Bytes> {
        if !self.is_garden(&ctx.host) {
            return Err(Error::WrongHost);
        }
        let bearer = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
        let mut community = self.community_backend()?.lock().await;
        with_live_clock(community.finish_root_issuance(bearer, request, ctx.now)).await
    }
}
