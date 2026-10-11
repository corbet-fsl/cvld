//! Explicit root host construction; no member request selects this mode.
use super::*;
use crate::config::RootCommunityConfig;

impl Door {
    /// Internal root board with mandatory joint proof and a roots-only garden.
    pub async fn root_board(config: RootCommunityConfig, clock: Arc<dyn Clock>) -> Result<Self> {
        let (community, descriptor) = config.into_parts()?;
        Self::community_with_optional_payment_transport(community, clock, None, Some(descriptor))
            .await
    }
}
