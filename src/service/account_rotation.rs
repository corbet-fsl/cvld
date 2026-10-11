//! Provisioned host-only signer rotation, never an HTTP/member action.
use super::*;

impl Door {
    /// Rotate this configured community's provisioned Policy signer, reconcile
    /// its same durable native ledger and refresh original publication owners.
    /// Supply only a key from the application's existing secret-store lifecycle.
    /// Any possibly committed failed/abandoned tail fences and starts native
    /// cleanup. Returned errors await its actual join outside the Community lock;
    /// callers must still await shutdown before tearing down the database runtime.
    pub async fn rotate_account_signer(&self, key: csgn::SecretKey) -> Result<()> {
        let runtime = self
            .inner
            .account_runtime
            .clone()
            .ok_or(Error::Unavailable)?;
        let shutdown = self
            .inner
            .account_shutdown
            .clone()
            .ok_or(Error::Unavailable)?;
        let backend = self.community_backend()?;
        let mut community = backend.lock().await;
        runtime.observe()?;
        if !community
            .account_runtime()
            .is_some_and(|actual| Arc::ptr_eq(&actual, &runtime))
        {
            return Err(Error::Unavailable);
        }
        // Capture cleanup before the first possibly durable Policy write. Drop
        // starts the SAME dedicated join when this future is abandoned; it never
        // claims actual completion. Explicit error cleanup awaits it below.
        let startup = crate::accounting::startup::Startup::new(Some(runtime), Some(shutdown));
        let result = community.rotate_account_signer(key).await;
        drop(community);
        startup.finish(result).await.map_err(|_| Error::Reconcile)
    }
}
