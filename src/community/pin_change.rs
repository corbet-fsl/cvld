//! Original native spend verification joined to the live member session.
use super::*;

impl CommunityService {
    pub(crate) async fn change_native_pin(
        &self,
        bearer: &str,
        request: PinChange,
        admitted_at: u64,
    ) -> Result<cmbr::Pin> {
        let runtime = self.accounts.as_ref().ok_or(Error::Unavailable)?;
        crate::service::with_live_clock(async {
            let mut now = pin_time(runtime, admitted_at.max(runtime.floor()), u64::MAX)?;
            let (grant, authentication) = self.authenticate_current(bearer, now).await?;
            now = pin_time(runtime, now, grant.expires)?;
            self.refresh_global(now).await?;
            now = pin_time(runtime, now, grant.expires)?;
            let original = self
                .facade
                .snapshot(now)
                .await
                .map_err(Error::Refused.redact())?;
            let mut until = grant
                .expires
                .min(original.valid_until)
                .min(original.passport.valid_until);
            now = pin_time(runtime, now, until)?;
            // This original signed envelope bounds scheduled Rulebook changes
            // during the final host awaits. Release its lease before the native
            // owner acquires that same Policy itself.
            {
                let mut policy = self.facade.policy().lock().await;
                now = pin_time(runtime, now, until)?;
                let settings = policy
                    .verified_settings(now)
                    .await
                    .map_err(Error::Refused.redact())?;
                if settings.settings().policy_epoch != original.rules.policy_epoch {
                    return Err(Error::Refused);
                }
                until = until.min(settings.valid_until());
                now = pin_time(runtime, now, until)?;
            }
            crate::service::publication::expires_at(until)?;
            let expected = self
                .facade
                .membership()
                .get_pin(&authentication, &request.field)
                .await
                .map_err(Error::Refused.redact())?
                .ok_or(Error::Refused)?;
            pin_time(runtime, now, until)?;
            let pin = self
                .facade
                .change_pin(
                    &authentication,
                    cmty::PinChange {
                        field: &request.field,
                        expected,
                        replacement: &request.pin,
                        evidence: &request.evidence,
                    },
                    until,
                    || runtime.native_time(),
                )
                .await
                .map_err(|error| match error {
                    cmty::Error::Reconcile => Error::Reconcile,
                    cmty::Error::AccountUnavailable => Error::Unavailable,
                    _ => Error::Refused,
                })?;
            // The owner may have committed the pin. Retain Policy -> Member
            // ordering after its original leases have returned; every failed
            // tail only withholds output, never claims the receipt is unspent.
            let completed = async {
                now = pin_time(runtime, now, until)?;
                let mut policy = self.facade.policy().lock().await;
                now = pin_time(runtime, now, until)?;
                let settings = policy
                    .verified_settings(now)
                    .await
                    .map_err(Error::Refused.redact())?;
                if settings.settings().policy_epoch != original.rules.policy_epoch {
                    return Err(Error::Refused);
                }
                until = until.min(settings.valid_until());
                crate::service::publication::expires_at(until)?;
                now = pin_time(runtime, now, until)?;
                let (current, auth) = self.authenticate_current(bearer, now).await?;
                pin_time(runtime, now, until)?;
                if current.session_id != grant.session_id
                    || current.user != grant.user
                    || current.credential != grant.credential
                    || current.expires != grant.expires
                    || current.role != grant.role
                    || !Arc::ptr_eq(&authentication, &auth)
                {
                    return Err(Error::Unauthorized);
                }
                Ok(pin)
            }
            .await;
            completed.map_err(|_| Error::Reconcile)
        })
        .await
    }
}

fn pin_time(
    runtime: &crate::accounting::clock::AccountRuntime,
    floor: u64,
    until: u64,
) -> Result<u64> {
    let now = runtime.observe()?;
    if now < floor || now >= until {
        return Err(Error::Unauthorized);
    }
    Ok(now)
}
