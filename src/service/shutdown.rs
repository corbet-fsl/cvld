//! Native lifecycle ownership stays outside an in-flight handler's mutex.
use super::*;

impl Door {
    /// Stop native intake and start cancellation synchronously. A host owning
    /// several Doors must call this on ALL of them before awaiting any join.
    /// This does not establish completion; retain and await `shutdown_accounts`.
    pub fn begin_shutdown_accounts(&self) -> Result<()> {
        if let Some(wallet) = &self.inner.wallet_shutdown {
            wallet.begin_shutdown();
        }
        if let Some(runtime) = &self.inner.account_runtime {
            runtime.fence();
        }
        let construction = self
            .inner
            .construction
            .as_ref()
            .map(|owner| owner.begin_shutdown());
        let accounts = self
            .inner
            .account_shutdown
            .as_ref()
            .map(|owner| owner.begin_shutdown().map_err(Error::Unavailable.redact()));
        construction.transpose()?;
        accounts.transpose()?;
        Ok(())
    }
    /// Irreversibly fence configured community work, cancel its actual native
    /// verifier pools and join the single worker before closing the DB runtime.
    /// Repeated or cancelled waiters share the owner's same joined result.
    /// A global or unconfigured community door has no native account worker.
    pub async fn shutdown_accounts(&self) -> Result<()> {
        let started = self.begin_shutdown_accounts();
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
        // Intake for BOTH owners was fenced above before any join. The caller
        // retains its one original total budget across these waits.
        if let Some(wallet) = &self.inner.wallet_shutdown {
            wallet.shutdown().await;
        }
        started?;
        accounts?;
        constructed?;
        Ok(())
    }
}
