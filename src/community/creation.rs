//! The creator's claim of the first admin seat of a community being created.
use super::*;
use crate::{
    api::{CreationClaim, CreationClaimed},
    hosts::Boxed,
    service::Context,
};

/// Terms of a community shell, verified against the registry by the hosting hub.
pub struct Terms {
    /// Creation id presented later as `creation` in `credential_issue`.
    pub id: String,
    /// Exclusive deadline of the claim.
    pub valid_until: u64,
}

/// Registry-backed check of a claim secret, supplied by the hosting hub only for
/// a community that is still being created.
pub trait CreationGate: Send + Sync {
    /// Verify the secret for this community's shell and return its terms.
    fn check<'a>(&'a self, secret: &'a [u8], now: u64) -> Boxed<'a, Result<Terms>>;
    /// The creator's first-admin admission committed: the community goes live.
    /// Best effort; the hub's sweep reconciles a failure.
    fn completed<'a>(&'a self) -> Boxed<'a, Result<()>>;
}

impl CommunityService {
    /// Whether the creator's first-admin admission has committed.
    pub(crate) async fn creation_active(&self) -> Result<bool> {
        Ok(self
            .facade
            .membership()
            .community_phase()
            .await
            .map_err(Error::Unavailable.redact())?
            == cmbr::CommunityPhase::Active)
    }

    /// The community's founding (genesis) document, if it has one.
    pub(crate) async fn genesis(&self) -> Result<Option<Vec<u8>>> {
        crate::genesis_store::load(&self.db, &self.config.community).await
    }

    /// Called after a successful admission that redeemed a creation id.
    pub(crate) async fn creation_completed(&self) {
        if let Some(gate) = &self.creation_gate {
            let _ = gate.completed().await;
        }
    }

    pub(crate) fn set_creation_gate(&mut self, gate: Arc<dyn CreationGate>) {
        self.creation_gate = Some(gate);
    }

    /// Bind the first seat to the member who is still joining and holds the
    /// shell's claim secret. First claim wins; Membership refuses any other
    /// creator for the same shell.
    pub(crate) async fn creation_claim(
        &mut self,
        ctx: &Context,
        request: CreationClaim,
    ) -> Result<CreationClaimed> {
        let gate = self.creation_gate.clone().ok_or(Error::Refused)?;
        let session = self.admission_session(ctx)?;
        let now = self.clock.now();
        session.release(now)?;
        let row = self
            .facade
            .membership()
            .resume(&session.authentication)
            .await
            .map_err(Error::Refused.redact())?;
        // Promotion of an admitted or lapsed member is never an entitlement.
        if !matches!(
            row.state(),
            cmbr::State::PasskeyRegistered
                | cmbr::State::HandleReserved
                | cmbr::State::GatesInProgress
        ) {
            return Err(Error::Refused);
        }
        let terms = gate.check(&request.claim, now).await?;
        self.facade
            .membership()
            .initialize_community_creation(&terms.id, row.subject().as_bytes(), terms.valid_until)
            .await
            .map_err(|error| {
                if error == cmbr::Error::Unavailable {
                    Error::Reconcile
                } else {
                    Error::Refused
                }
            })?;
        session.release(self.clock.now())?;
        Ok(CreationClaimed {
            id: terms.id,
            expires_at: terms.valid_until,
        })
    }
}

/// One-time claim armed by the launcher for a statically configured community
/// that is created without the registry hub (for example the Root board).
pub(crate) struct StaticGate {
    pub(crate) hash: [u8; 32],
    pub(crate) valid_until: u64,
}

impl StaticGate {
    pub(crate) fn hash(secret: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest([b"cvld.claim.v1\0".as_slice(), secret].concat()).into()
    }
}

impl CreationGate for StaticGate {
    fn check<'a>(&'a self, secret: &'a [u8], now: u64) -> Boxed<'a, Result<Terms>> {
        use subtle::ConstantTimeEq;
        Box::pin(async move {
            let matches: bool = Self::hash(secret).ct_eq(&self.hash).into();
            if !matches || now >= self.valid_until {
                return Err(Error::Refused);
            }
            Ok(Terms {
                id: crate::hub::hex(&self.hash[..16]),
                valid_until: self.valid_until,
            })
        })
    }
    fn completed<'a>(&'a self) -> Boxed<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Ends this community on behalf of its admins; supplied by the hosting hub.
pub trait Lifecycle: Send + Sync {
    fn dissolve<'a>(&'a self, now: u64) -> Boxed<'a, Result<()>>;
}

impl CommunityService {
    pub(crate) fn set_lifecycle(&mut self, lifecycle: Arc<dyn Lifecycle>) {
        self.lifecycle = Some(lifecycle);
    }

    /// The hub's lifecycle handle; the caller drops this service's lock before
    /// using it, because ending shuts the very door that holds the lock.
    pub(crate) fn lifecycle(&self) -> Result<Arc<dyn Lifecycle>> {
        self.lifecycle.clone().ok_or(Error::Refused)
    }
}
