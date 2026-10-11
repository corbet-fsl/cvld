//! Original public-only root-board host configuration.
use super::*;

/// Explicit operator configuration for the internal root community. The extra
/// file contains only the canonical PUBLIC CPSD descriptor; no root issuer
/// secret or source-community membership is supplied to admission.
/// Its scope and purpose key are configuration. The service projects the
/// current Policy epoch and aligned cohort instead of freezing file counters.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCommunityConfig {
    community: CommunityConfig,
    root_board_public_key_file: String,
}

impl RootCommunityConfig {
    /// Preserve the configured native shutdown budget of this community.
    pub fn shutdown_budget(&self) -> Result<Duration> {
        self.community.shutdown_budget()
    }
    pub fn listen(&self) -> &str {
        &self.community.listen
    }

    pub fn new(community: CommunityConfig, root_board_public_key_file: String) -> Result<Self> {
        if community.community != "root" || root_board_public_key_file.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            community,
            root_board_public_key_file,
        })
    }

    pub fn read(path: &str) -> Result<Self> {
        let config: Self =
            serde_json::from_slice(&std::fs::read(path).map_err(|_| Error::Unavailable)?)
                .map_err(|_| Error::Invalid)?;
        Self::new(config.community, config.root_board_public_key_file)
    }

    pub(crate) fn into_parts(self) -> Result<(CommunityConfig, cpsd::RootBoardPublicKey)> {
        if self.community.community != "root" || self.root_board_public_key_file.is_empty() {
            return Err(Error::Invalid);
        }
        let descriptor = cpsd::RootBoardPublicKey::from_bytes(
            &std::fs::read(&self.root_board_public_key_file).map_err(|_| Error::Unavailable)?,
        )
        .map_err(|_| Error::Invalid)?;
        if descriptor.community().as_bytes() != b"root" {
            return Err(Error::Invalid);
        }
        Ok((self.community, descriptor))
    }
}
