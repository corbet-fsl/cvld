//! Same current credential only; opaque commitments confer no root authority.
use super::*;
use std::time::Duration;

impl Auth {
    pub(crate) async fn initial_creation(
        &mut self,
        token: &str,
        bind: Option<InitialPublicationBind>,
        admitted_at: u64,
        clock: &dyn Clock,
    ) -> Result<InitialCreationResponse> {
        if self.role != Role::Member || self.operator.is_some() {
            return Err(Error::Forbidden);
        }
        use crate::refusal::{Reason, note_for, refuse};
        let started = Instant::now();
        let admitted = self
            .sessions
            .get(token)
            .ok_or_else(|| refuse(Reason::SessionMissing))?
            .grant
            .clone();
        let remaining = admitted.expires.checked_sub(admitted_at).ok_or_else(|| {
            note_for(Reason::SessionExpired, &admitted.user, &admitted.session_id);
            Error::Unauthorized
        })?;
        let deadline = started
            .checked_add(Duration::from_secs(remaining))
            .ok_or_else(|| refuse(Reason::TimeInvalid))?;
        let grant = self.authenticate(token, admitted_at).await?;
        let original = self
            .sessions
            .get(token)
            .ok_or_else(|| refuse(Reason::SessionChanged))?
            .authentication
            .clone();
        let now = fresh(clock, admitted_at, grant.expires, deadline)?;
        crate::service::publication::expires_at(grant.expires)?;
        let writing = bind.is_some();
        let keys = self.passkeys.clone();
        let authentication = original.clone();
        let state = tokio::task::spawn_blocking(move || match bind {
            Some(bind) => {
                keys.bind_initial_publication(&authentication, bind.seed, bind.publication)
            }
            None => keys.initial_creation(&authentication),
        })
        .await
        .map_err(|_| {
            if writing {
                Error::Reconcile
            } else {
                Error::Unavailable
            }
        })?
        .map_err(|error| {
            if writing && error == ckyh::Error::Storage {
                Error::Reconcile
            } else {
                Error::Refused
            }
        })?;
        // The CAS may already be durable: ALL later failures are uncertainty,
        // including current-key validation and the final clock observation.
        let result = async {
            let now = fresh(clock, now, grant.expires, deadline)?;
            let current = self.authenticate(token, now).await?;
            let session = self
                .sessions
                .get(token)
                .ok_or_else(|| refuse(Reason::SessionChanged))?;
            if current.user != grant.user
                || current.credential != grant.credential
                || current.session_id != grant.session_id
                || current.expires != grant.expires
                || !Arc::ptr_eq(&session.authentication, &original)
            {
                note_for(Reason::SessionChanged, &grant.user, &grant.session_id);
                return Err(Error::Unauthorized);
            }
            let checked_at = fresh(clock, now, grant.expires, deadline)?;
            Ok(InitialCreationResponse {
                seed: state.seed(),
                publication: state.publication(),
                checked_at,
                nonce: None,
            })
        }
        .await;
        result.map_err(|error| if writing { Error::Reconcile } else { error })
    }
}
