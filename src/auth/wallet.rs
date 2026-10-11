//! Exact original wallet Auth session retained through certificate/publication.
use super::*;
use std::time::{Duration, Instant};

pub(crate) struct WalletSession {
    grant: Grant,
    authentication: Arc<ckyh::Authentication>,
    floor: Option<u64>,
    deadline: Instant,
}
impl WalletSession {
    pub(crate) fn member(&self) -> Result<&ckyh::Authentication> {
        self.floor.ok_or(Error::Unauthorized)?;
        Ok(&self.authentication)
    }
    pub(crate) fn expires(&self) -> u64 {
        self.grant.expires
    }
    pub(crate) fn checked_at(&self) -> Result<u64> {
        self.floor.ok_or(Error::Unauthorized)
    }
    fn sample(&mut self, now: u64, previous: u64) -> Result<u64> {
        if now < previous || now >= self.grant.expires || Instant::now() >= self.deadline {
            return Err(Error::Unauthorized);
        }
        crate::service::publication::expires_at(self.grant.expires)?;
        Ok(now)
    }
    fn same(&self, auth: &Auth, token: &str, grant: &Grant) -> Result<()> {
        let current = auth.sessions.get(token).ok_or(Error::Unauthorized)?;
        if grant.user != self.grant.user
            || grant.credential != self.grant.credential
            || grant.session_id != self.grant.session_id
            || grant.expires != self.grant.expires
            || grant.role != Role::Member
            || current.grant.session_id != self.grant.session_id
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
        previous: u64,
        clock: &dyn crate::service::Clock,
    ) -> Result<u64> {
        let floor = self.floor.take().ok_or(Error::Unauthorized)?.max(previous);
        let now = self.sample(clock.now(), floor)?;
        let grant = auth.authenticate(token, now).await?;
        self.same(auth, token, &grant)?;
        let completed = self.sample(clock.now(), now)?;
        self.floor = Some(completed);
        Ok(completed)
    }
    pub(crate) fn check_sync(
        &mut self,
        auth: &Auth,
        token: &str,
        previous: u64,
        clock: &dyn crate::service::Clock,
    ) -> Result<u64> {
        let floor = self.floor.take().ok_or(Error::Unauthorized)?.max(previous);
        self.same(
            auth,
            token,
            &auth.sessions.get(token).ok_or(Error::Unauthorized)?.grant,
        )?;
        let completed = self.sample(clock.now(), floor)?;
        self.floor = Some(completed);
        Ok(completed)
    }
}
impl Auth {
    pub(crate) async fn wallet_session(
        &mut self,
        token: &str,
        admitted: &Grant,
        admitted_at: u64,
        clock: &dyn crate::service::Clock,
    ) -> Result<WalletSession> {
        if self.role != Role::Member || self.operator.is_some() {
            return Err(Error::Forbidden);
        }
        let started = Instant::now();
        let now = clock.now();
        if now < admitted_at || now >= admitted.expires {
            return Err(Error::Unauthorized);
        }
        let deadline = started
            .checked_add(Duration::from_secs(admitted.expires - now))
            .ok_or(Error::Unauthorized)?;
        let grant = self.authenticate(token, now).await?;
        let authentication = self
            .sessions
            .get(token)
            .ok_or(Error::Unauthorized)?
            .authentication
            .clone();
        if authentication.community() != "wallet"
            || grant.user != admitted.user
            || grant.credential != admitted.credential
            || grant.session_id != admitted.session_id
            || grant.expires != admitted.expires
            || grant.role != Role::Member
        {
            return Err(Error::Unauthorized);
        }
        let mut session = WalletSession {
            grant,
            authentication,
            floor: None,
            deadline,
        };
        let completed = session.sample(clock.now(), now)?;
        session.floor = Some(completed);
        Ok(session)
    }
}

// Test timing surrounds the original SDK operation only. There is no public
// seam, replacement transport, authentication fact or mutation verdict.
#[cfg(test)]
pub(crate) struct WorkerGate {
    pub(crate) after: bool,
    pub(crate) arrived: tokio::sync::Notify,
    released: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}
#[cfg(test)]
impl WorkerGate {
    pub(crate) fn new(after: bool) -> Arc<Self> {
        Arc::new(Self {
            after,
            arrived: tokio::sync::Notify::new(),
            released: std::sync::Mutex::new(false),
            wake: std::sync::Condvar::new(),
        })
    }
    pub(crate) fn wait(&self) {
        self.arrived.notify_one();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
    }
    pub(crate) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
