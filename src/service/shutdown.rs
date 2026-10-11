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
        // One caller-retained group may own other factories in addition to this
        // Door. Withdraw all their native execution before waiting for any join.
        let construction_started = if let Some(construction) = &self.inner.construction {
            construction.begin_shutdown()
        } else {
            Ok(())
        };
        let accounts_started = if let Some(shutdown) = &self.inner.account_shutdown {
            shutdown
                .begin_shutdown()
                .map_err(Error::Unavailable.redact())
        } else {
            Ok(())
        };
        let accounts = if let Some(shutdown) = &self.inner.account_shutdown {
            shutdown
                .shutdown()
                .await
                .map_err(Error::Unavailable.redact())
        } else {
            Ok(())
        };
        let constructed = if let Some(construction) = &self.inner.construction {
            construction.shutdown().await
        } else {
            Ok(())
        };
        construction_started?;
        accounts_started?;
        accounts?;
        constructed?;
        Ok(())
    }
}
