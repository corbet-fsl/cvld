//! Validate explicitly supplied configuration without provisioning garden roles.
use super::*;

pub(super) fn validate_operators(config: &CommunityConfig) -> Result<()> {
    // The legacy admin field grants no garden authentication. Keeping its
    // declared data validation avoids silently ignoring malformed capabilities.
    for operator in [&config.root, &config.admin] {
        if let Some(path) = &operator.bootstrap_file {
            let secret = Config::secret(path)?;
            let text = std::str::from_utf8(&secret).map_err(Error::Invalid.redact())?;
            if !(32..=1024).contains(&text.len()) {
                return Err(Error::Invalid);
            }
        }
    }
    Ok(())
}
