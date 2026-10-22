//! The birth grant of the one-ceremony registration (C1, C2).
//!
//! A wallet session minted by the registration itself, by a passkey login, or by a fork of
//! those may run each birth action (device bind, genesis statement, first stamp, birth
//! passport) without another passkey ceremony while ALL of these hold, rechecked at each use:
//! the account has exactly one live passkey and it is the session's credential; the minting
//! user verification is at most T_birth old; the action's birth item is open or holds the same
//! input (cgbl owns the items). The caller keeps this Auth locked from the check through the
//! action, so no passkey of this Auth can be added in between; cgbl rechecks the one-passkey
//! rule inside its own commit for the device bind.
use super::*;

/// T_birth: how long after the minting user verification a session may use the birth grant.
/// A code constant, not a setting: it is technical mechanics nobody tunes; it either works or
/// it does not. 30 minutes covers the birth actions including a slow Tor publication; a
/// restart's passkey login is a fresh user verification and starts a new window.
pub(crate) const BIRTH_UV_WINDOW: u64 = 30 * 60;

impl Auth {
    /// Mint the birth session of a just-finished registration (C1). The capacity was checked
    /// before the ceremony was consumed.
    pub(super) fn birth_session(
        &mut self,
        credential: ckyh::CredentialID,
        authentication: ckyh::Authentication,
        now: u64,
    ) -> Result<Session> {
        let token = token();
        let user = authentication.member();
        let expires = now + self.lifetime;
        crate::service::publication::expires_at(expires)?;
        let session_id = rand::random();
        self.sessions.insert(
            token.clone(),
            SessionState {
                grant: Grant {
                    user,
                    role: self.role,
                    expires,
                    credential,
                    origin: ckyh::Origin::Passkey,
                    session_id,
                    uv_at: Some(now),
                },
                authentication: Arc::new(authentication),
                family: session_id,
            },
        );
        Ok(Session {
            token,
            user: user.to_string(),
            role: self.role,
            expires,
        })
    }

    /// Check the birth grant (C2) of session `token` at `now`. Every failure is `Forbidden`
    /// (an expired or revoked session stays `Unauthorized`). The birth item itself is checked
    /// by cgbl in the action's own compare-and-swap.
    pub(crate) async fn birth_grant(&mut self, token: &str, now: u64) -> Result<Grant> {
        if self.role != Role::Member || self.operator.is_some() {
            return Err(Error::Forbidden);
        }
        let grant = self.authenticate(token, now).await?;
        let session = self.sessions.get(token).ok_or(Error::Unauthorized)?;
        if session.authentication.community() != "wallet"
            || grant.role != Role::Member
            || grant.origin != ckyh::Origin::Passkey
        {
            return Err(Error::Forbidden);
        }
        let uv_at = grant.uv_at.ok_or(Error::Forbidden)?;
        if now < uv_at || now - uv_at > BIRTH_UV_WINDOW {
            return Err(Error::Forbidden);
        }
        let passkeys = self.passkeys.clone();
        let (user, credential) = (grant.user, grant.credential.clone());
        let sole = tokio::task::spawn_blocking(move || {
            passkeys.is_sole_live_credential(user, &credential)
        })
        .await
        .map_err(Error::Unavailable.redact())?
        .map_err(Error::Unavailable.redact())?;
        if !sole {
            return Err(Error::Forbidden);
        }
        Ok(grant)
    }
}
