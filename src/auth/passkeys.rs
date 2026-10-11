//! Equal-standing management of passkeys for the exact authenticated account.
use super::*;

pub(super) struct PendingAddition {
    state: PendingRegistration,
    pub(super) session_id: [u8; 32],
    authorizer: ckyh::CredentialID,
    pub(super) until: u64,
}

impl Auth {
    pub async fn list_passkeys(&mut self, token: &str, now: u64) -> Result<PasskeyList> {
        let grant = self.authenticate(token, now).await?;
        let keys = self.passkeys.clone();
        let records = tokio::task::spawn_blocking(move || keys.list(grant.user))
            .await
            .map_err(Error::Unavailable.redact())?
            .map_err(Error::Refused.redact())?;
        Ok(PasskeyList::from_records(records, &grant.credential))
    }

    pub async fn add_passkey(
        &mut self,
        token: &str,
        request: AddPasskey,
        now: u64,
    ) -> Result<AddedPasskey> {
        self.add_passkey_wallet(token, request, now, None).await
    }

    pub(crate) async fn add_passkey_wallet(
        &mut self,
        token: &str,
        request: AddPasskey,
        now: u64,
        mutation: Option<cgbl::WalletMutation>,
    ) -> Result<AddedPasskey> {
        if mutation
            .as_ref()
            .is_some_and(|owner| !owner.matches(&self.passkeys))
        {
            return Err(Error::Unauthorized);
        }
        let grant = self.authenticate(token, now).await?;
        let authentication = self
            .sessions
            .get(token)
            .ok_or(Error::Unauthorized)?
            .authentication
            .clone();
        match request {
            AddPasskey::Begin => {
                self.additions
                    .retain(|_, pending| pending.session_id != grant.session_id);
                // One addition per live session; the existing session limit
                // bounds this map, and each addition expires with its session.
                let keys = self.passkeys.clone();
                let (options, state) = tokio::task::spawn_blocking(move || {
                    keys.start_additional_registration(&authentication)
                })
                .await
                .map_err(Error::Unavailable.redact())?
                .map_err(Error::Refused.redact())?;
                let until = now.saturating_add(300).min(grant.expires);
                crate::service::publication::expires_at(until)?;
                let id = super::token();
                self.additions.insert(
                    id.clone(),
                    PendingAddition {
                        state,
                        session_id: grant.session_id,
                        authorizer: grant.credential,
                        until,
                    },
                );
                Ok(AddedPasskey::Challenge {
                    ceremony: id,
                    user: grant.user.to_string(),
                    options: serde_json::to_value(options).map_err(Error::Unavailable.redact())?,
                })
            }
            AddPasskey::Finish {
                ceremony,
                credential,
            } => {
                let pending = self.additions.get(&ceremony).ok_or(Error::Unauthorized)?;
                if pending.session_id != grant.session_id || pending.authorizer != grant.credential
                {
                    return Err(Error::Unauthorized);
                }
                let pending = self
                    .additions
                    .remove(&ceremony)
                    .ok_or(Error::Unauthorized)?;
                crate::service::publication::expires_at(pending.until)?;
                let month = creation_month(now)?;
                let keys = self.passkeys.clone();
                let operation = move |keys: &Passkeys<LibsqlStore>| {
                    keys.finish_registration(pending.state, &credential, month)
                };
                let record = match mutation {
                    Some(owner) => owner.execute(operation).await,
                    None => tokio::task::spawn_blocking(move || operation(&keys))
                        .await
                        .map_err(Error::Unavailable.redact())?,
                }
                .map_err(Error::Refused.redact())?;
                Ok(AddedPasskey::Registered {
                    user: record.member().to_string(),
                    credential: record.credential_id().as_ref().to_vec(),
                })
            }
        }
    }

    pub async fn revoke_passkey(
        &mut self,
        token: &str,
        credential: ckyh::CredentialID,
        now: u64,
    ) -> Result<()> {
        self.revoke_passkey_wallet(token, credential, now, None)
            .await
    }

    pub(crate) async fn revoke_passkey_wallet(
        &mut self,
        token: &str,
        credential: ckyh::CredentialID,
        now: u64,
        mutation: Option<cgbl::WalletMutation>,
    ) -> Result<()> {
        if mutation
            .as_ref()
            .is_some_and(|owner| !owner.matches(&self.passkeys))
        {
            return Err(Error::Unauthorized);
        }
        let grant = self.authenticate(token, now).await?;
        let keys = self.passkeys.clone();
        let target = credential.clone();
        #[cfg(test)]
        let gate = self.wallet_worker_gate.clone();
        let operation = move |keys: &Passkeys<LibsqlStore>| {
            #[cfg(test)]
            if let Some(gate) = &gate {
                if !gate.after {
                    gate.wait();
                }
            }
            let result = keys.revoke(grant.user, &target);
            #[cfg(test)]
            if let Some(gate) = &gate {
                if gate.after {
                    gate.wait();
                }
            }
            result
        };
        match mutation {
            Some(owner) => owner.execute(operation).await,
            None => tokio::task::spawn_blocking(move || operation(&keys))
                .await
                .map_err(Error::Unavailable.redact())?,
        }
        .map_err(Error::Refused.redact())?;
        self.sessions
            .retain(|_, session| session.grant.credential != credential);
        self.additions
            .retain(|_, pending| pending.authorizer != credential);
        self.self_bans
            .retain(|_, pending| pending.authorizer != credential);
        Ok(())
    }
}
