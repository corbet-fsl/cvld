//! Provisioned host tuning, never a member or operator HTTP action.
use super::*;
use cblc::accounting_ledger::WaitingPeriodTuning;

impl Door {
    /// Change future native reservation waiting periods through the existing
    /// configured owner and refresh its original authenticated publication.
    /// The host must authorize this independently of member requests. The
    /// expected native revision prevents overwriting another host's decision.
    /// Failed or abandoned tails conservatively fence the same runtime; returned
    /// errors await actual native cleanup outside the Community mutex. Await
    /// shutdown before tearing down the original DB runtime after cancellation.
    pub async fn tune_account_waiting_period(
        &self,
        expected_revision: u64,
        seconds: u64,
    ) -> Result<WaitingPeriodTuning> {
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
        let mut community = self.community_backend()?.lock().await;
        runtime.observe()?;
        if !community
            .account_runtime()
            .is_some_and(|actual| Arc::ptr_eq(&actual, &runtime))
        {
            return Err(Error::Unavailable);
        }
        // The same native worker and cleanup handle are held before any write.
        let startup = crate::accounting::startup::Startup::new(Some(runtime), Some(shutdown));
        let result = community
            .tune_account_waiting_period(expected_revision, seconds)
            .await;
        drop(community);
        startup.finish(result).await.map_err(|_| Error::Reconcile)
    }
}
