//! Retrieve an original registered-key certificate, never an admission credential.
use super::*;

impl CommunityService {
    pub async fn certificate(
        &self,
        bearer: &str,
        admitted_at: u64,
    ) -> Result<PasskeyCertificateResponse> {
        crate::service::with_live_clock(async {
            let mut now = self.clock.now();
            if now < admitted_at {
                return Err(Error::Unauthorized);
            }
            let (grant, authentication) = self.authenticate_current(bearer, now).await?;
            crate::service::publication::expires_at(grant.expires)?;
            let observed = self.clock.now();
            if observed < now || observed >= grant.expires {
                return Err(Error::Unauthorized);
            }
            now = observed;
            // Original cmty owns Policy -> Membership lease order, real Keyhole
            // projection, signing, and post-await lifecycle/certificate checks.
            let issued = self
                .facade
                .passkey_certificate(&authentication, now)
                .await
                .map_err(Error::Refused.redact())?;
            self.finish_issued_certificate(bearer, grant, issued, now)
                .await
        })
        .await
    }

    /// Carry the original completed owner observation across this await boundary.
    async fn finish_issued_certificate(
        &self,
        bearer: &str,
        grant: crate::auth::Grant,
        issued: cmty::PasskeyCertificate,
        prior: u64,
    ) -> Result<PasskeyCertificateResponse> {
        let observed = self.clock.now();
        if observed < prior || observed < issued.checked_at() || observed >= grant.expires {
            return Err(Error::Unauthorized);
        }
        self.final_certificate(bearer, grant, issued.into_bytes(), observed)
            .await
    }

    /// Retain the original Policy owner through the final current-key check and
    /// synchronous output verification. Inputs come only from this composition's
    /// genuine authenticated session and original certificate issuer.
    async fn final_certificate(
        &self,
        bearer: &str,
        grant: crate::auth::Grant,
        bytes: Vec<u8>,
        observed: u64,
    ) -> Result<PasskeyCertificateResponse> {
        // Preserve the original Policy -> Membership order for the final
        // current-key check. No owner lock is awaited after that check.
        let policy = self.facade.policy().lock().await;
        let observed_after_lock = self.clock.now();
        if observed_after_lock < observed || observed_after_lock >= grant.expires {
            return Err(Error::Unauthorized);
        }
        let (current, _) = self
            .authenticate_current(bearer, observed_after_lock)
            .await?;
        let completed = self.clock.now();
        if current.session_id != grant.session_id
            || current.user != grant.user
            || current.credential != grant.credential
            || completed < observed_after_lock
            || completed >= grant.expires
        {
            return Err(Error::Unauthorized);
        }
        // The session check may wait. Verify the original signed lifetime
        // again at the actual output boundary, with no intervening await.
        policy
            .key_ring()
            .map_err(Error::Refused.redact())?
            .verify(&bytes, csgn::Kind::Credential, completed)
            .map_err(Error::Refused.redact())?;
        Ok(PasskeyCertificateResponse {
            bytes,
            checked_at: completed,
        })
    }
}

#[cfg(all(test, feature = "development-gate"))]
mod tests;
