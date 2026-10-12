//! Step-up assertions for passkey, device and revocation actions on Auth hosts.
use super::*;
use crate::{
    api::{StepUpAction, StepUpChallenge, StepUpProof},
    service::Clock,
    step_up::Binding,
};

impl Auth {
    pub(crate) async fn step_up_begin(
        &mut self,
        token: &str,
        host: &str,
        action: StepUpAction,
        now: u64,
        clock: &dyn Clock,
    ) -> Result<StepUpChallenge> {
        let grant = self.authenticate(token, now).await?;
        let plan = self.step_ups.plan(&grant, now, clock)?;
        let keys = self.passkeys.clone();
        let credential = grant.credential.clone();
        let user = grant.user;
        let (options, state) =
            tokio::task::spawn_blocking(move || keys.start_authentication_for(user, &credential))
                .await
                .map_err(Error::Unavailable.redact())?
                .map_err(Error::Unauthorized.redact())?;
        let options = serde_json::to_value(options).map_err(Error::Unavailable.redact())?;
        let binding = Binding {
            host,
            action: &action,
        };
        self.step_ups
            .insert(plan, &grant, binding, state, options, clock)
    }

    /// Consume the challenge and verify its user-verifying assertion against
    /// this session's own, still unrevoked credential.
    pub(crate) async fn step_up_consume(
        &mut self,
        token: &str,
        binding: Binding<'_>,
        proof: StepUpProof,
        now: u64,
        clock: &dyn Clock,
        mutation: Option<cgbl::WalletMutation>,
    ) -> Result<()> {
        if mutation
            .as_ref()
            .is_some_and(|owner| !owner.matches(&self.passkeys))
        {
            return Err(Error::Unauthorized);
        }
        let grant = self.authenticate(token, now).await?;
        let (state, receipt) = self
            .step_ups
            .take(&proof.ceremony, &grant, binding, now, clock)?;
        let keys = self.passkeys.clone();
        let operation = move |keys: &Passkeys<LibsqlStore>| {
            keys.finish_authentication(state, &proof.credential)
        };
        let authentication = match mutation {
            Some(owner) => owner.execute(operation).await,
            None => tokio::task::spawn_blocking(move || operation(&keys))
                .await
                .map_err(Error::Unavailable.redact())?,
        }
        .map_err(Error::Unauthorized.redact())?;
        let verified = authentication.member() == grant.user
            && authentication.credential_id() == &grant.credential;
        receipt.complete(verified, clock)
    }
}
