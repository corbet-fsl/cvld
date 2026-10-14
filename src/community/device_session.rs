//! Sessions opened by a registered device key, without any passkey prompt. The server issues a
//! one-use nonce; the device signs it; the key must be ACTIVE for that member in this community.
//! Renewal is the same exchange. Every refusal after the nonce lookup is the same `Unauthorized`.
use super::*;
use crate::device_registry::{self, State};
use crate::device_session::{NONCE_LEN, NONCE_SECONDS, message};
use ed25519_dalek::{Signature, VerifyingKey};

pub(super) struct DeviceSession {
    pub member: String,
    pub device_key: [u8; 32],
    pub expires: u64,
}

impl CommunityService {
    /// JOIN HOOK, see `device_registry::bind_first_device_key`.
    pub(crate) async fn bind_first_device_key(
        &self,
        member: ckyh::Uuid,
        device_key: &[u8; 32],
    ) -> Result<()> {
        device_registry::bind_first_device_key(
            &self.db,
            &self.config.community,
            &member.to_string(),
            device_key,
        )
        .await
    }

    pub async fn device_session_begin(&mut self, now: u64) -> Result<DeviceSessionChallenge> {
        self.prune(now);
        if self.device_nonces.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        let nonce: [u8; NONCE_LEN] = rand::random();
        crate::service::publication::expires_at(now + NONCE_SECONDS)?;
        self.device_nonces.insert(nonce, now);
        Ok(DeviceSessionChallenge { nonce, issued: now })
    }

    pub async fn device_session_finish(
        &mut self,
        request: DeviceSessionFinish,
        now: u64,
    ) -> Result<Session> {
        self.prune(now);
        if self.device_sessions.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        // Single use: the nonce is spent whatever follows.
        let issued = self
            .device_nonces
            .remove(&request.nonce)
            .ok_or(Error::Unauthorized)?;
        if now < issued || now >= issued.saturating_add(NONCE_SECONDS) {
            return Err(Error::Unauthorized);
        }
        let key =
            VerifyingKey::from_bytes(&request.device_key).map_err(Error::Unauthorized.redact())?;
        let signature =
            Signature::from_slice(&request.signature).map_err(Error::Unauthorized.redact())?;
        key.verify_strict(
            &message(&self.config.community, &request.nonce, issued),
            &signature,
        )
        .map_err(Error::Unauthorized.redact())?;
        let user = ckyh::Uuid::parse_str(&request.user).map_err(Error::Unauthorized.redact())?;
        let member = user.to_string();
        if device_registry::state(
            &self.db,
            &self.config.community,
            &member,
            &request.device_key,
        )
        .await?
            != Some(State::Active)
        {
            return Err(Error::Unauthorized);
        }
        let expires = now
            .checked_add(self.config.session_seconds)
            .ok_or(Error::Invalid)?;
        crate::service::publication::expires_at(expires)?;
        let id = token();
        self.device_sessions.insert(
            id.clone(),
            DeviceSession {
                member: member.clone(),
                device_key: request.device_key,
                expires,
            },
        );
        Ok(Session {
            token: id,
            user: member,
            role: Role::Member,
            expires,
        })
    }

    /// The member behind a live device session, only while its key is still active. This is
    /// not yet wired into request authorization: those actions still take a passkey session.
    pub async fn device_session_member(&self, token: &str, now: u64) -> Result<String> {
        let session = self
            .device_sessions
            .get(token)
            .filter(|session| now < session.expires)
            .ok_or(Error::Unauthorized)?;
        match device_registry::state(
            &self.db,
            &self.config.community,
            &session.member,
            &session.device_key,
        )
        .await?
        {
            Some(State::Active) => Ok(session.member.clone()),
            _ => Err(Error::Unauthorized),
        }
    }
}
