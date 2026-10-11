//! Bounded process-local sessions. Authentication is exclusively ckyh.
use crate::{
    api::*,
    error::{Error, Result},
};
use ckyh::{LibsqlStore, Passkeys, PendingAuthentication, PendingRegistration, Uuid};
use std::{collections::HashMap, sync::Arc};
use subtle::ConstantTimeEq;

mod enrollment;
pub(crate) mod global_self_ban;
mod passkeys;

pub struct Auth {
    pub passkeys: Arc<Passkeys<LibsqlStore>>,
    pub role: Role,
    pub operator: Option<Uuid>,
    pub bootstrap: Option<zeroize::Zeroizing<String>>,
    registrations: HashMap<String, Pending<PendingRegistration>>,
    logins: HashMap<String, PendingLogin>,
    sessions: HashMap<String, SessionState>,
    additions: HashMap<String, passkeys::PendingAddition>,
    self_bans: HashMap<String, global_self_ban::PendingSelfBan>,
    capacity: usize,
    lifetime: u64,
}

#[cfg(test)]
mod tests;
struct Pending<T> {
    state: T,
    user: Uuid,
    expires: u64,
    observed: u64,
    deadline: std::time::Instant,
    initial: Option<([u8; 32], serde_json::Value)>,
}
struct PendingLogin {
    state: LoginCeremony,
    expires: u64,
}
struct SessionState {
    grant: Grant,
    authentication: Arc<ckyh::Authentication>,
}
enum LoginCeremony {
    Credential(PendingAuthentication),
    Discoverable(ckyh::PendingDiscoverableAuthentication),
}
#[derive(Clone)]
pub struct Grant {
    pub user: Uuid,
    pub role: Role,
    pub expires: u64,
    pub(crate) credential: ckyh::CredentialID,
    pub(crate) session_id: [u8; 32],
}
/// Random opaque bearer capability, without embedded member information.
pub fn token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
impl Auth {
    pub fn new(
        passkeys: Passkeys<LibsqlStore>,
        role: Role,
        operator: Option<Uuid>,
        bootstrap: Option<zeroize::Zeroizing<String>>,
        capacity: usize,
        lifetime: u64,
    ) -> Result<Self> {
        if capacity == 0
            || lifetime == 0
            || lifetime > 3600
            || bootstrap
                .as_ref()
                .is_some_and(|capability| !(32..=1024).contains(&capability.len()))
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            passkeys: Arc::new(passkeys),
            role,
            operator,
            bootstrap,
            registrations: HashMap::new(),
            logins: HashMap::new(),
            sessions: HashMap::new(),
            additions: HashMap::new(),
            self_bans: HashMap::new(),
            capacity,
            lifetime,
        })
    }
    fn prune(&mut self, now: u64) {
        self.registrations
            .retain(|_, p| p.expires > now && std::time::Instant::now() < p.deadline);
        self.logins.retain(|_, p| p.expires > now);
        self.sessions.retain(|_, p| p.grant.expires > now);
        self.additions.retain(|_, p| p.until > now);
        self.self_bans.retain(|_, p| p.until > now);
    }
    pub async fn register_begin(&mut self, request: RegisterStart, now: u64) -> Result<Ceremony> {
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(300))
            .ok_or(Error::Invalid)?;
        let expires = now.checked_add(300).ok_or(Error::Invalid)?;
        self.prune(now);
        if self.registrations.len() >= self.capacity {
            return Err(Error::Throttled);
        }
        if request.passport.is_some() {
            return Err(Error::Invalid);
        }
        let user = if let Some(operator) = self.operator {
            // Bootstrap is a provisioned random capability, never a caller-selected role.
            if !self
                .bootstrap
                .as_ref()
                .zip(request.bootstrap.as_ref())
                .is_some_and(|(expected, supplied)| {
                    bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
                })
            {
                return Err(Error::Forbidden);
            }
            operator
        } else {
            if request.bootstrap.is_some() {
                return Err(Error::Forbidden);
            }
            Uuid::new_v4()
        };
        let passkeys = self.passkeys.clone();
        let passkeys_role = self.role == Role::Member && self.operator.is_none();
        let (options, state) = tokio::task::spawn_blocking(move || {
            if !passkeys.list(user)?.is_empty() {
                return Err(ckyh::Error::DuplicateCredential);
            }
            if passkeys_role {
                passkeys.start_initial_registration(user, None)
            } else {
                passkeys.start_registration(user)
            }
        })
        .await
        .map_err(Error::Unavailable.redact())?
        .map_err(Error::Refused.redact())?;
        let ceremony = token();
        crate::service::publication::expires_at(expires)?;
        self.registrations.insert(
            ceremony.clone(),
            Pending {
                state,
                user,
                expires,
                observed: now,
                deadline,
                initial: None,
            },
        );
        Ok(Ceremony {
            ceremony,
            user: user.to_string(),
            options: serde_json::to_value(options).map_err(Error::Unavailable.redact())?,
        })
    }
    #[cfg(test)]
    pub async fn register_finish(&mut self, request: RegisterFinish, now: u64) -> Result<User> {
        self.register_finish_live(request, now, &enrollment::FixedClock(now))
            .await
    }
    pub(crate) async fn register_finish_live(
        &mut self,
        request: RegisterFinish,
        now: u64,
        clock: &dyn crate::service::Clock,
    ) -> Result<User> {
        self.prune(now);
        let pending = self
            .registrations
            .remove(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        let completed_user = pending.user;
        let observed = enrollment::pending_time(&pending, now, clock)?;
        crate::service::publication::expires_at(pending.expires)?;
        let month = creation_month(now)?;
        let expires = pending.expires;
        let deadline = pending.deadline;
        let passkeys = self.passkeys.clone();
        tokio::task::spawn_blocking(move || {
            if !passkeys.list(pending.user)?.is_empty() {
                return Err(ckyh::Error::DuplicateCredential);
            }
            passkeys.finish_registration(pending.state, &request.credential, month)
        })
        .await
        .map_err(Error::Reconcile.redact())?
        .map_err(|error| {
            if error == ckyh::Error::Storage {
                Error::Reconcile
            } else {
                Error::Refused
            }
        })?;
        enrollment::fresh(clock, observed, expires, deadline).map_err(|_| Error::Reconcile)?;
        if self.operator.is_some() {
            self.bootstrap = None;
        }
        Ok(User {
            user: completed_user.to_string(),
        })
    }
    pub async fn login_begin(&mut self, request: LoginStart, now: u64) -> Result<Ceremony> {
        self.prune(now);
        if self.logins.len() >= self.capacity {
            return Err(Error::Throttled);
        }
        let user = Uuid::parse_str(&request.user).map_err(Error::Invalid.redact())?;
        if self.operator.is_some_and(|operator| operator != user) {
            return Err(Error::Unauthorized);
        }
        let passkeys = self.passkeys.clone();
        let (options, state) = tokio::task::spawn_blocking(move || {
            passkeys.start_authentication_for(user, &request.credential.into())
        })
        .await
        .map_err(Error::Unavailable.redact())?
        .map_err(Error::Unauthorized.redact())?;
        let ceremony = token();
        crate::service::publication::expires_at(now + 300)?;
        self.logins.insert(
            ceremony.clone(),
            PendingLogin {
                state: LoginCeremony::Credential(state),
                expires: now + 300,
            },
        );
        Ok(Ceremony {
            ceremony,
            user: user.to_string(),
            options: serde_json::to_value(options).map_err(Error::Unavailable.redact())?,
        })
    }
    pub async fn login_discoverable_begin(&mut self, now: u64) -> Result<DiscoverableCeremony> {
        self.prune(now);
        if self.logins.len() >= self.capacity {
            return Err(Error::Throttled);
        }
        let passkeys = self.passkeys.clone();
        let (options, state) =
            tokio::task::spawn_blocking(move || passkeys.start_discoverable_authentication())
                .await
                .map_err(Error::Unavailable.redact())?
                .map_err(Error::Unauthorized.redact())?;
        let ceremony = token();
        crate::service::publication::expires_at(now + 300)?;
        self.logins.insert(
            ceremony.clone(),
            PendingLogin {
                state: LoginCeremony::Discoverable(state),
                expires: now + 300,
            },
        );
        Ok(DiscoverableCeremony {
            ceremony,
            options: serde_json::to_value(options).map_err(Error::Unavailable.redact())?,
        })
    }
    pub async fn login_finish(&mut self, request: LoginFinish, now: u64) -> Result<Session> {
        self.prune(now);
        if self.sessions.len() >= self.capacity {
            return Err(Error::Throttled);
        }
        let pending = self
            .logins
            .remove(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        crate::service::publication::expires_at(pending.expires)?;
        let credential: ckyh::CredentialID = request.credential.raw_id.clone().into();
        let passkeys = self.passkeys.clone();
        let authentication = tokio::task::spawn_blocking(move || match pending.state {
            LoginCeremony::Credential(state) => {
                passkeys.finish_authentication(state, &request.credential)
            }
            LoginCeremony::Discoverable(state) => {
                passkeys.finish_discoverable_authentication(state, &request.credential)
            }
        })
        .await
        .map_err(Error::Unavailable.redact())?
        .map_err(Error::Unauthorized.redact())?;
        if self
            .operator
            .is_some_and(|operator| operator != authentication.member())
        {
            return Err(Error::Unauthorized);
        }
        let token = token();
        let user = authentication.member();
        let expires = now + self.lifetime;
        crate::service::publication::expires_at(expires)?;
        self.sessions.insert(
            token.clone(),
            SessionState {
                grant: Grant {
                    user,
                    role: self.role,
                    expires,
                    credential,
                    session_id: rand::random(),
                },
                authentication: Arc::new(authentication),
            },
        );
        Ok(Session {
            token,
            user: user.to_string(),
            role: self.role,
            expires,
        })
    }
    pub async fn authenticate(&mut self, token: &str, now: u64) -> Result<Grant> {
        self.prune(now);
        let grant = self
            .sessions
            .get(token)
            .map(|session| session.grant.clone())
            .ok_or(Error::Unauthorized)?;
        let passkeys = self.passkeys.clone();
        let user = grant.user;
        let credential = grant.credential.clone();
        let live = tokio::task::spawn_blocking(move || {
            passkeys.list(user).map(|records| {
                records
                    .iter()
                    .any(|r| !r.is_revoked() && r.credential_id() == &credential)
            })
        })
        .await
        .map_err(Error::Unavailable.redact())?
        .map_err(Error::Unauthorized.redact())?;
        if !live {
            self.logout(token);
            return Err(Error::Unauthorized);
        }
        Ok(grant)
    }
    pub fn logout(&mut self, token: &str) {
        if let Some(session) = self.sessions.remove(token) {
            self.additions
                .retain(|_, p| p.session_id != session.grant.session_id);
            self.self_bans
                .retain(|_, p| p.session_id != session.grant.session_id);
        }
    }

    pub(crate) fn logout_account(&mut self, user: Uuid) {
        self.sessions
            .retain(|_, session| session.grant.user != user);
        let live: std::collections::HashSet<_> = self
            .sessions
            .values()
            .map(|session| session.grant.session_id)
            .collect();
        self.additions
            .retain(|_, pending| live.contains(&pending.session_id));
        self.self_bans
            .retain(|_, pending| live.contains(&pending.session_id));
    }
}

fn creation_month(now: u64) -> Result<ckyh::CreationMonth> {
    use chrono::Datelike;
    let seconds = i64::try_from(now).map_err(Error::Invalid.redact())?;
    let date = chrono::DateTime::from_timestamp(seconds, 0).ok_or(Error::Invalid)?;
    let year = u16::try_from(date.year()).map_err(Error::Invalid.redact())?;
    ckyh::CreationMonth::new(year, date.month() as u8).map_err(Error::Invalid.redact())
}
