//! Additional passkeys use membership authorization and the normal WebAuthn verifier.
use super::*;

pub(super) struct PendingAddition {
    pub value: cmbr::PendingAdditionalRegistration,
    pub session_id: [u8; 32],
    pub credential: cpky::CredentialID,
    pub until: u64,
}

impl CommunityService {
    pub async fn add_passkey(
        &mut self,
        authentication: &cpky::Authentication,
        grant: &Grant,
        request: AddPasskey,
        now: u64,
    ) -> Result<AddedPasskey> {
        self.prune(now);
        if !self.sessions.values().any(|session| {
            session.grant.session_id == grant.session_id
                && session.grant.user == authentication.member()
                && session.grant.credential == *authentication.credential_id()
        }) {
            return Err(Error::Unauthorized);
        }
        match request {
            AddPasskey::Begin => {
                // One outstanding ceremony per session; retries replace old state.
                self.additions
                    .retain(|_, p| p.session_id != grant.session_id);
                if self.additions.len() >= self.config.pending_capacity {
                    return Err(Error::Throttled);
                }
                let (options, value) = self
                    .facade
                    .begin_additional_registration(authentication)
                    .await
                    .map_err(|_| Error::Refused)?;
                let id = token();
                self.additions.insert(
                    id.clone(),
                    PendingAddition {
                        value,
                        session_id: grant.session_id,
                        credential: grant.credential.clone(),
                        until: now.saturating_add(300).min(grant.expires),
                    },
                );
                Ok(AddedPasskey::Challenge {
                    ceremony: id,
                    user: grant.user.to_string(),
                    options: serde_json::to_value(options).map_err(|_| Error::Unavailable)?,
                })
            }
            AddPasskey::Finish {
                ceremony,
                credential,
            } => {
                let pending = self.additions.get(&ceremony).ok_or(Error::Unauthorized)?;
                if pending.session_id != grant.session_id {
                    return Err(Error::Unauthorized);
                }
                let pending = self
                    .additions
                    .remove(&ceremony)
                    .ok_or(Error::Unauthorized)?;
                let record = self
                    .facade
                    .finish_additional_registration(authentication, pending.value, *credential)
                    .await
                    .map_err(|_| Error::Refused)?;
                Ok(AddedPasskey::Registered {
                    user: record.member().to_string(),
                    credential: record.credential_id().as_ref().to_vec(),
                })
            }
        }
    }

    pub fn revoke_sessions(&mut self, credential: &cpky::CredentialID) {
        self.sessions
            .retain(|_, session| session.grant.credential != *credential);
        self.additions
            .retain(|_, pending| pending.credential != *credential);
    }
}
