//! Explicit root host construction; no member request selects this mode.
use super::*;
use crate::config::RootCommunityConfig;

impl Door {
    /// Internal root board with mandatory joint proof and a roots-only garden.
    pub async fn root_board(config: RootCommunityConfig, clock: Arc<dyn Clock>) -> Result<Self> {
        Self::root_board_with_construction(config, clock, NativeConstruction::new()).await
    }
    /// Caller-retained construction owner for cancellation before a Door exists.
    pub async fn root_board_with_construction(
        config: RootCommunityConfig,
        clock: Arc<dyn Clock>,
        construction: NativeConstruction,
    ) -> Result<Self> {
        let (community, descriptor) = config.into_parts()?;
        Self::community_with_optional_payment_transport(
            community,
            clock,
            None,
            Some(descriptor),
            construction,
        )
        .await
    }
}
