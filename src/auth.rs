//! Bounded process-local sessions. Authentication is exclusively ckyh.
use crate::{
    api::*,
    error::{Error, Result},
};
use ckyh::{LibsqlStore, Passkeys, PendingAuthentication, PendingRegistration, Uuid};
use std::{collections::HashMap, sync::Arc};
use subtle::ConstantTimeEq;

pub struct Auth {
    pub passkeys: Arc<Passkeys<LibsqlStore>>,
    pub role: Role,
    pub operator: Option<Uuid>,
    pub bootstrap: Option<zeroize::Zeroizing<String>>,
    registrations: HashMap<String, Pending<PendingRegistration>>,
    logins: HashMap<String, PendingLogin>,
    sessions: HashMap<String, Grant>,
    capacity: usize,
    lifetime: u64,
}
struct Pending<T> {
    state: T,
    user: Uuid,
    expires: u64,
}
struct PendingLogin {
    state: LoginCeremony,
    expires: u64,
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
            capacity,
            lifetime,
        })
    }
    fn prune(&mut self, now: u64) {
        self.registrations.retain(|_, p| p.expires > now);
        self.logins.retain(|_, p| p.expires > now);
        self.sessions.retain(|_, p| p.expires > now);
    }
    pub async fn register_begin(&mut self, request: RegisterStart, now: u64) -> Result<Ceremony> {
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
        let (options, state) = tokio::task::spawn_blocking(move || {
            if !passkeys.list(user)?.is_empty() {
                return Err(ckyh::Error::DuplicateCredential);
            }
            passkeys.start_registration(user)
        })
        .await
        .map_err(|_| Error::Unavailable)?
        .map_err(|_| Error::Refused)?;
        let ceremony = token();
        self.registrations.insert(
            ceremony.clone(),
            Pending {
                state,
                user,
                expires: now + 300,
            },
        );
        Ok(Ceremony {
            ceremony,
            user: user.to_string(),
            options: serde_json::to_value(options).map_err(|_| Error::Unavailable)?,
        })
    }
    pub async fn register_finish(&mut self, request: RegisterFinish, now: u64) -> Result<User> {
        self.prune(now);
        let pending = self
            .registrations
            .remove(&request.ceremony)
            .ok_or(Error::Unauthorized)?;
        let date = chrono::DateTime::from_timestamp(now as i64, 0).ok_or(Error::Invalid)?;
        use chrono::Datelike;
        let month = ckyh::CreationMonth::new(date.year() as u16, date.month() as u8)
            .map_err(|_| Error::Invalid)?;
        let passkeys = self.passkeys.clone();
        tokio::task::spawn_blocking(move || {
            if !passkeys.list(pending.user)?.is_empty() {
                return Err(ckyh::Error::DuplicateCredential);
            }
            passkeys.finish_registration(pending.state, &request.credential, month)
        })
        .await
        .map_err(|_| Error::Unavailable)?
        .map_err(|_| Error::Refused)?;
        if self.operator.is_some() {
            self.bootstrap = None;
        }
        Ok(User {
            user: pending.user.to_string(),
        })
    }
    pub async fn login_begin(&mut self, request: LoginStart, now: u64) -> Result<Ceremony> {
        self.prune(now);
        if self.logins.len() >= self.capacity {
            return Err(Error::Throttled);
        }
        let user = Uuid::parse_str(&request.user).map_err(|_| Error::Invalid)?;
        if self.operator.is_some_and(|operator| operator != user) {
            return Err(Error::Unauthorized);
        }
        let passkeys = self.passkeys.clone();
        let (options, state) = tokio::task::spawn_blocking(move || {
            passkeys.start_authentication_for(user, &request.credential.into())
        })
        .await
        .map_err(|_| Error::Unavailable)?
        .map_err(|_| Error::Unauthorized)?;
        let ceremony = token();
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
            options: serde_json::to_value(options).map_err(|_| Error::Unavailable)?,
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
                .map_err(|_| Error::Unavailable)?
                .map_err(|_| Error::Unauthorized)?;
        let ceremony = token();
        self.logins.insert(
            ceremony.clone(),
            PendingLogin {
                state: LoginCeremony::Discoverable(state),
                expires: now + 300,
            },
        );
        Ok(DiscoverableCeremony {
            ceremony,
            options: serde_json::to_value(options).map_err(|_| Error::Unavailable)?,
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
        .map_err(|_| Error::Unavailable)?
        .map_err(|_| Error::Unauthorized)?;
        if self
            .operator
            .is_some_and(|operator| operator != authentication.member())
        {
            return Err(Error::Unauthorized);
        }
        let token = token();
        let expires = now + self.lifetime;
        self.sessions.insert(
            token.clone(),
            Grant {
                user: authentication.member(),
                role: self.role,
                expires,
                credential,
                session_id: rand::random(),
            },
        );
        Ok(Session {
            token,
            user: authentication.member().to_string(),
            role: self.role,
            expires,
        })
    }
    pub async fn authenticate(&mut self, token: &str, now: u64) -> Result<Grant> {
        self.prune(now);
        let grant = self
            .sessions
            .get(token)
            .cloned()
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
        .map_err(|_| Error::Unavailable)?
        .map_err(|_| Error::Unauthorized)?;
        if !live {
            self.sessions.remove(token);
            return Err(Error::Unauthorized);
        }
        Ok(grant)
    }
    pub fn logout(&mut self, token: &str) {
        self.sessions.remove(token);
    }
}
