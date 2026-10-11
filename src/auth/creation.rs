//! Exact platform Root session retained through a separate target transaction.
use super::*;
use crate::service::Clock;
use std::time::{Duration, Instant};

pub(crate) struct RootCreationSession {
    grant: Grant,
    authentication: Arc<ckyh::Authentication>,
    floor: Option<u64>,
    deadline: Instant,
}
impl Auth {
    pub(crate) async fn root_creation_session(
        &mut self,
        token: &str,
        expected: &Grant,
        observed: u64,
        clock: &dyn Clock,
    ) -> Result<RootCreationSession> {
        let started = Instant::now();
        let now = clock.now();
        if now < observed || now >= expected.expires || self.role != Role::Root {
            return Err(Error::Unauthorized);
        }
        let grant = self.authenticate(token, now).await?;
        let current = self.sessions.get(token).ok_or(Error::Unauthorized)?;
        if grant.session_id != expected.session_id
            || grant.user != expected.user
            || grant.credential != expected.credential
            || grant.expires != expected.expires
            || grant.role != Role::Root
            || self.operator != Some(grant.user)
        {
            return Err(Error::Unauthorized);
        }
        let mut result = RootCreationSession {
            deadline: started
                .checked_add(Duration::from_secs(grant.expires - now))
                .ok_or(Error::Unauthorized)?,
            grant,
            authentication: current.authentication.clone(),
            floor: Some(now),
        };
        result.release(self, token, clock)?;
        Ok(result)
    }
}
impl RootCreationSession {
    fn same(&self, auth: &Auth, token: &str) -> Result<()> {
        let current = auth.sessions.get(token).ok_or(Error::Unauthorized)?;
        if auth.role != Role::Root
            || auth.operator != Some(self.grant.user)
            || current.grant.session_id != self.grant.session_id
            || current.grant.user != self.grant.user
            || current.grant.credential != self.grant.credential
            || current.grant.expires != self.grant.expires
            || current.grant.role != Role::Root
            || !Arc::ptr_eq(&current.authentication, &self.authentication)
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    pub(crate) async fn check(
        &mut self,
        auth: &mut Auth,
        token: &str,
        clock: &dyn Clock,
    ) -> Result<u64> {
        let observed = self.release(auth, token, clock)?;
        self.floor = None;
        auth.authenticate(token, observed).await?;
        self.same(auth, token)?;
        self.floor = Some(observed);
        self.release(auth, token, clock)
    }
    pub(crate) fn release(&mut self, auth: &Auth, token: &str, clock: &dyn Clock) -> Result<u64> {
        let previous = self.floor.take().ok_or(Error::Unauthorized)?;
        self.same(auth, token)?;
        let now = clock.now();
        if now < previous || now >= self.grant.expires || Instant::now() >= self.deadline {
            return Err(Error::Unauthorized);
        }
        crate::service::publication::expires_at(now)?;
        self.floor = Some(now);
        Ok(now)
    }
}
