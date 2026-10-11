//! Native lifecycle ownership stays outside an in-flight handler's mutex.
use super::*;

impl Door {
    /// Irreversibly fence configured community work, cancel its actual native
    /// verifier pools and join the single worker before closing the DB runtime.
    /// Repeated or cancelled waiters share the owner's same joined result.
    /// A global or unconfigured community door has no native account worker.
    pub async fn shutdown_accounts(&self) -> Result<()> {
        if let Some(runtime) = &self.inner.account_runtime {
            runtime.fence();
        }
        if let Some(shutdown) = &self.inner.account_shutdown {
            shutdown
                .shutdown()
                .await
                .map_err(Error::Unavailable.redact())?;
        }
        Ok(())
    }
}
