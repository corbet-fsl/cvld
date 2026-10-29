//! Wallet session renewal by the wallet device key K (A13; DESIGN-secure-convenience 3.2-3.4).
//! A passkey login anchors its family to (member, C, K) (M1/M2). Before the newest generation
//! expires, the device signs a one-use nonce with K and receives a NEW member of the same family
//! in the next generation (no token is ever extended). Each renewal checks that K is still C's
//! binding (M4) and that C is live. The chain has no lifetime limit: only revocation (removing
//! the anchor) or an explicit logout ends it. Every refusal after the nonce lookup is the same
//! `Unauthorized`.
use super::*;
use crate::device_session::{NONCE_LEN, NONCE_SECONDS, wallet_message};
use ed25519_dalek::{Signature, VerifyingKey};

/// A family renews only when its newest generation has at most this much time left (or is
/// gone), so one K holds at most two live generations per family.
pub const RENEW_WINDOW_SECONDS: u64 = 300;
/// Bound on pending renewal nonces and anchors held by one Auth.
const CAPACITY: usize = 100_000;

/// One anchor: the family a passkey login of credential C opened, bound to K.
#[derive(Clone)]
struct Anchor {
    /// The authenticating host's passkey community (the wallet's).
    community: String,
    member: Uuid,
    credential: ckyh::CredentialID,
    device_key: [u8; 32],
}

#[derive(Default)]
pub(crate) struct Renewals {
    nonces: HashMap<[u8; NONCE_LEN], u64>,
    anchors: HashMap<[u8; 32], Anchor>,
}

impl Renewals {
    pub(super) fn prune(&mut self, now: u64) {
        self.nonces
            .retain(|_, issued| now < issued.saturating_add(NONCE_SECONDS));
    }
    pub(super) fn anchored(&self, member: Uuid, device_key: [u8; 32], family: &[u8; 32]) -> bool {
        self.anchors
            .get(family)
            .is_some_and(|anchor| anchor.member == member && anchor.device_key == device_key)
    }
    pub(super) fn forget_family(&mut self, family: &[u8; 32]) {
        self.anchors.remove(family);
    }
    pub(super) fn forget_member(&mut self, member: Uuid) {
        self.anchors.retain(|_, anchor| anchor.member != member);
    }
}

impl Auth {
    /// Anchor the family of the live passkey session `token` to the wallet device key K (M2:
    /// called inside the passkey login once K's possession is proven, or at the birth bind).
    pub(crate) async fn anchor_wallet_device(
        &mut self,
        token: &str,
        device_key: [u8; 32],
        now: u64,
    ) -> Result<()> {
        let grant = self.authenticate(token, now).await?;
        if grant.origin != ckyh::Origin::Passkey {
            return Err(Error::Unauthorized);
        }
        let (family, community) = self
            .sessions
            .get(token)
            .map(|session| {
                (
                    session.family,
                    session.authentication.community().to_owned(),
                )
            })
            .ok_or(Error::Unauthorized)?;
        if !self.renewals.anchors.contains_key(&family) && self.renewals.anchors.len() >= CAPACITY {
            return Err(Error::Throttled);
        }
        self.renewals.anchors.insert(
            family,
            Anchor {
                community,
                member: grant.user,
                credential: grant.credential,
                device_key,
            },
        );
        Ok(())
    }

    /// Revoke K for `member`: every family anchored to it ends now and can never renew.
    pub(crate) async fn revoke_wallet_device(
        &mut self,
        member: Uuid,
        device_key: [u8; 32],
    ) -> Result<()> {
        let families: Vec<[u8; 32]> = self
            .renewals
            .anchors
            .iter()
            .filter(|(_, anchor)| anchor.member == member && anchor.device_key == device_key)
            .map(|(family, _)| *family)
            .collect();
        for family in &families {
            self.renewals.anchors.remove(family);
        }
        self.sessions
            .retain(|_, session| !families.contains(&session.family));
        self.retain_live();
        Ok(())
    }

    /// Issue a one-use renewal nonce.
    pub async fn wallet_renew_begin(&mut self, now: u64) -> Result<DeviceSessionChallenge> {
        self.prune(now);
        if self.renewals.nonces.len() >= self.capacity.min(CAPACITY) {
            return Err(Error::Throttled);
        }
        let nonce: [u8; NONCE_LEN] = rand::random();
        crate::service::publication::expires_at(now + NONCE_SECONDS)?;
        self.renewals.nonces.insert(nonce, now);
        Ok(DeviceSessionChallenge { nonce, issued: now })
    }

    /// Renew the anchored family by K's signature. `bound(member, C, K)` is the wallet's current
    /// binding check (M4): K must still be C's bound device key.
    pub async fn wallet_renew(
        &mut self,
        host: &str,
        request: WalletSessionRenew,
        now: u64,
        bound: &(dyn Fn(Uuid, &ckyh::CredentialID, [u8; 32]) -> bool + Sync),
    ) -> Result<Session> {
        self.prune(now);
        if self.sessions.len() >= self.capacity {
            return Err(Error::Throttled);
        }
        // Single use: the nonce is spent whatever follows.
        let issued = self
            .renewals
            .nonces
            .remove(&request.nonce)
            .ok_or(Error::Unauthorized)?;
        if now < issued || now >= issued.saturating_add(NONCE_SECONDS) {
            return Err(Error::Unauthorized);
        }
        let user = Uuid::parse_str(&request.account).map_err(|_| Error::Unauthorized)?;
        let key = VerifyingKey::from_bytes(&request.device_key).map_err(|_| Error::Unauthorized)?;
        if key.is_weak() {
            return Err(Error::Unauthorized);
        }
        let signature =
            Signature::from_slice(&request.signature).map_err(|_| Error::Unauthorized)?;
        key.verify_strict(
            &wallet_message(
                host,
                user.as_bytes(),
                &request.family,
                &request.nonce,
                issued,
            ),
            &signature,
        )
        .map_err(|_| Error::Unauthorized)?;
        // M1: an anchor of exactly this member, K and family.
        let anchor = self
            .renewals
            .anchors
            .get(&request.family)
            .filter(|anchor| anchor.member == user && anchor.device_key == request.device_key)
            .cloned()
            .ok_or(Error::Unauthorized)?;
        // M4: K is still C's current binding.
        if !bound(user, &anchor.credential, request.device_key) {
            return Err(Error::Unauthorized);
        }
        // C is live (not revoked).
        let passkeys = self.passkeys.clone();
        let credential = anchor.credential.clone();
        let live = tokio::task::spawn_blocking(move || {
            passkeys.list(user).map(|records| {
                records
                    .iter()
                    .any(|r| !r.is_revoked() && r.credential_id() == &credential)
            })
        })
        .await
        .map_err(|_| Error::Unauthorized)?
        .map_err(|_| Error::Unauthorized)?;
        if !live {
            return Err(Error::Unauthorized);
        }
        // Renewal window: the newest generation is gone or expires within the window.
        let newest = self
            .sessions
            .values()
            .filter(|session| session.family == request.family)
            .map(|session| (session.generation, session.grant.expires))
            .max();
        if newest.is_some_and(|(_, expires)| expires > now.saturating_add(RENEW_WINDOW_SECONDS)) {
            return Err(Error::Unauthorized);
        }
        let generation = match newest {
            Some((generation, _)) => generation.checked_add(1).ok_or(Error::Unauthorized)?,
            None => 1,
        };
        let expires = now.checked_add(self.lifetime).ok_or(Error::Invalid)?;
        crate::service::publication::expires_at(expires)?;
        let token = token();
        self.sessions.insert(
            token.clone(),
            SessionState {
                grant: Grant {
                    user,
                    role: self.role,
                    expires,
                    credential: anchor.credential,
                    origin: ckyh::Origin::DeviceKey,
                    session_id: rand::random(),
                    // A renewal never carries the birth grant (C2).
                    uv_at: None,
                },
                authentication: Arc::new(ckyh::Authentication::from_device_key(
                    anchor.community,
                    user,
                    request.device_key,
                )),
                family: request.family,
                generation,
            },
        );
        Ok(Session {
            token,
            user: user.to_string(),
            role: self.role,
            expires,
        })
    }
}
