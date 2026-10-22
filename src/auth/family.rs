//! Session families (C6, `session_fork`). A fork is a sibling of a live session: the same
//! account, credential, role, authentication and deadline under a fresh session id and bearer.
//! It adds no authority, because the parent's bearer can already do everything the sibling
//! can until the same deadline; it exists because a client-side lease holds its session
//! exclusively. A fork never renews: its deadline is its parent's. The family ends together:
//! logout, revocation of the shared credential, or the expiry of any member ends every member.
use super::*;

/// Live sessions per family (the login plus its forks) when the rulebook names no other.
pub const DEFAULT_FAMILY_LIMIT: usize = 3;
/// The largest family a rulebook may allow.
pub const MAX_FAMILY_LIMIT: usize = 8;

impl Auth {
    /// Set the family limit, checked when the configuration loads.
    pub fn set_family_limit(&mut self, limit: usize) -> Result<()> {
        if !(1..=MAX_FAMILY_LIMIT).contains(&limit) {
            return Err(Error::Invalid);
        }
        self.family_limit = limit;
        Ok(())
    }

    /// Fork the live session `parent` into a sibling of the same family. Per-action user
    /// verification (step-ups, stamps) stays per session: the sibling inherits no pending
    /// ceremony of its parent.
    pub async fn fork(&mut self, parent: &str, now: u64) -> Result<Session> {
        // Prunes expired families and ends this one if its credential was revoked.
        self.authenticate(parent, now).await?;
        let parent = self.sessions.get(parent).ok_or(Error::Unauthorized)?;
        if parent.grant.expires <= now {
            return Err(Error::Unauthorized);
        }
        if self.sessions.len() >= self.capacity {
            return Err(Error::Throttled);
        }
        let members = self
            .sessions
            .values()
            .filter(|session| session.family == parent.family)
            .count();
        if members >= self.family_limit {
            return Err(Error::Refused);
        }
        // Clone the whole state so every grant field the parent carries reaches the sibling;
        // only the session id is fresh. The deadline is the parent's: no renewal.
        let mut sibling = parent.clone();
        sibling.grant.session_id = rand::random();
        let grant = sibling.grant.clone();
        crate::service::publication::expires_at(grant.expires)?;
        let token = super::token();
        self.sessions.insert(token.clone(), sibling);
        Ok(Session {
            token,
            user: grant.user.to_string(),
            role: grant.role,
            expires: grant.expires,
        })
    }
}
