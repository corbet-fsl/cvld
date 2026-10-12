//! Step-up assertions for passkey, device and revocation actions on a community.
use super::*;
use crate::api::{StepUpAction, StepUpChallenge, StepUpProof};

impl CommunityService {
    fn step_up_session(&self, authentication: &ckyh::Authentication, grant: &Grant) -> Result<()> {
        if self.sessions.values().any(|session| {
            session.grant.session_id == grant.session_id
                && session.grant.user == authentication.member()
                && session.grant.credential == *authentication.credential_id()
        }) {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    pub(crate) async fn step_up_begin(
        &mut self,
        authentication: &ckyh::Authentication,
        grant: &Grant,
        host: &str,
        action: StepUpAction,
        now: u64,
    ) -> Result<StepUpChallenge> {
        self.prune(now);
        self.step_ups.prune(now);
        self.step_up_session(authentication, grant)?;
        let plan = self.step_ups.plan(grant, now, self.clock.as_ref())?;
        let (options, state) = self
            .facade
            .membership()
            .begin_login(grant.user, grant.credential.clone())
            .await
            .map_err(Error::Unauthorized.redact())?;
        let options = serde_json::to_value(options).map_err(Error::Unavailable.redact())?;
        self.step_ups.insert(
            plan,
            grant,
            host,
            action,
            state,
            options,
            self.clock.as_ref(),
        )
    }

    pub(crate) async fn step_up_consume(
        &mut self,
        authentication: &ckyh::Authentication,
        grant: &Grant,
        host: &str,
        action: &StepUpAction,
        proof: StepUpProof,
        now: u64,
    ) -> Result<()> {
        self.prune(now);
        self.step_up_session(authentication, grant)?;
        let (state, receipt) = self.step_ups.take(
            &proof.ceremony,
            grant,
            host,
            action,
            now,
            self.clock.as_ref(),
        )?;
        let login = self
            .facade
            .membership()
            .finish_login(state, proof.credential)
            .await
            .map_err(Error::Unauthorized.redact())?;
        let verified = login.authentication.member() == grant.user
            && login.authentication.credential_id() == &grant.credential;
        receipt.complete(verified, self.clock.as_ref())
    }
}
