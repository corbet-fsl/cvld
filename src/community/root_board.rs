//! Original current common descriptor projection, separate from source-role issuance.
use super::*;

impl CommunityService {
    pub(crate) async fn open_root_board(
        db: &crlt::Db,
        config: CommunityConfig,
        clock: Arc<dyn Clock>,
        descriptor: cpsd::RootBoardPublicKey,
        transport: Option<crate::payments::transport::AnyTransport>,
    ) -> Result<Self> {
        Self::open_selected(db, config, clock, transport, Some(descriptor)).await
    }

    pub(super) async fn maintain_root_board(&self, now: u64) -> Result<bool> {
        let Some(issuer) = &self.root_board_issuer else {
            return Ok(false);
        };
        let policy = self.facade.policy().lock().await;
        let expected = root_descriptor(
            issuer,
            &self.config.community,
            policy
                .epoch(now)
                .await
                .map_err(Error::Unavailable.redact())?,
            now,
        )?;
        let current = policy
            .root_board_descriptor(now)
            .await
            .ok()
            .flatten()
            .is_some_and(|(descriptor, _)| descriptor == expected);
        drop(policy);
        if !current {
            // Original Policy checks the immutable issuer and durable cohort
            // floor. Failure cannot restore or reset an incompatible owner.
            self.refresh_root_board(now).await?;
        }
        Ok(!current)
    }

    pub(super) async fn refresh_root_board(&self, now: u64) -> Result<()> {
        if let Some(issuer) = &self.root_board_issuer {
            let mut policy = self.facade.policy().lock().await;
            let descriptor = root_descriptor(
                issuer,
                &self.config.community,
                policy
                    .epoch(now)
                    .await
                    .map_err(Error::Unavailable.redact())?,
                now,
            )?;
            // Existing Policy retains the immutable issuer and cohort floor.
            // Publishing metadata never renews a holder's root credential.
            policy
                .publish_root_board(&descriptor, now)
                .await
                .map_err(Error::Unavailable.redact())?;
        }
        Ok(())
    }
}

pub(super) fn root_descriptor(
    issuer: &cpsd::IssuerPublicKey,
    community: &str,
    epoch: u64,
    now: u64,
) -> Result<cpsd::RootBoardPublicKey> {
    cpsd::RootBoardPublicKey::from_authenticated_beacon(
        issuer.clone(),
        cpsd::CommunityId::new(community).map_err(Error::Invalid.redact())?,
        epoch,
        now / cpsd::ROOT_BOARD_COHORT_SECONDS * cpsd::ROOT_BOARD_COHORT_SECONDS,
    )
    .map_err(Error::Invalid.redact())
}
