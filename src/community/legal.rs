//! Community-bound self-ban authority; qualified legal authority stays absent.
//!
//! A host checks the initiating session at begin, finish and submission. Only
//! cmbr's sealed, dedicated UV confirmation can mint this RAM capability. The
//! clbs verifier consumes it once, authenticating the complete immutable order.
//! A consumed capability does not prove that the subsequent append committed:
//! errors/cancellation require exact trusted-record reconciliation by the host.
use crate::{
    error::{Error, Result},
    service::Clock,
};
use cmty::cmbr;
use std::{collections::HashMap, sync::Arc};

/// Cloneable shared verifier for one community, without raw WebAuthn evidence.
#[derive(Clone)]
pub struct CommunityAuthority {
    community: String,
    clock: Arc<dyn Clock>,
    capacity: usize,
    confirmations: Arc<tokio::sync::Mutex<HashMap<Vec<u8>, cmbr::ConfirmedSelfBan>>>,
}

impl CommunityAuthority {
    /// Explicit composition only; no default trust, storage or credential lookup.
    pub fn new(community: &str, clock: Arc<dyn Clock>, capacity: usize) -> Result<Self> {
        if community.trim().is_empty()
            || community.len() > 1024
            || community.chars().any(char::is_control)
            || capacity == 0
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            community: community.into(),
            clock,
            capacity,
            confirmations: Arc::default(),
        })
    }

    /// Consume a sealed confirmation after the host rechecked its exact session.
    /// This returns ephemeral verifier evidence, never persistable authority.
    pub async fn authorize(
        &self,
        confirmation: cmbr::ConfirmedSelfBan,
    ) -> Result<clbs::SignedOrder> {
        let mut confirmations = self.confirmations.lock().await;
        let now = self.now().map_err(Error::Unauthorized.redact())?;
        confirmations.retain(|_, confirmation| confirmation.is_current(now));
        if confirmation.order().community != self.community || !confirmation.is_current(now) {
            return Err(Error::Unauthorized);
        }
        if confirmations.len() >= self.capacity {
            return Err(Error::Throttled);
        }
        let mut proof = crate::auth::token().into_bytes();
        while confirmations.contains_key(&proof) {
            proof = crate::auth::token().into_bytes();
        }
        let order = confirmation.order().clone();
        confirmations.insert(proof.clone(), confirmation);
        Ok(clbs::SignedOrder { order, proof })
    }

    fn now(&self) -> clbs::Result<i64> {
        // Authorization observes the actual live clock. An operation's frozen
        // proof timestamp must never prolong an irreversible confirmation.
        self.clock.now().try_into().map_err(|_| clbs::Error::Clock)
    }
}

impl clbs::Verifier for CommunityAuthority {
    async fn verify_legal(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        // A signature/key ring alone does not establish qualified legal authority
        // or the entering root actor. No qualifying adapter is configured.
        Err(clbs::Error::Denied)
    }

    async fn verify_self_ban(&self, order: &clbs::SignedOrder) -> clbs::Result<()> {
        let mut confirmations = self.confirmations.lock().await;
        let now = self.now()?;
        confirmations.retain(|_, confirmation| confirmation.is_current(now));
        let confirmed = confirmations
            .remove(&order.proof)
            .ok_or(clbs::Error::Denied)?;
        if order.order.community != self.community
            || confirmed.order() != &order.order
            || !confirmed.is_current(now)
        {
            return Err(clbs::Error::Denied);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
