//! Wallet session renewal by the wallet device key K (A13; DESIGN-secure-convenience 3.2-3.4).
//! A passkey login with K's proof of possession anchors its family to (member, C, K) in the
//! durable anchor table (M1/M2). Before the newest generation expires, the device signs a
//! one-use nonce with K and receives a NEW member of the same family in the next generation (no
//! token is ever extended). Each renewal checks that K is still C's binding (M4) and that C is
//! live. The chain has no lifetime limit: only revocation (removing the anchor) or an explicit
//! logout ends it. Every refusal after the nonce lookup is the same `Unauthorized`.
use super::*;
use crate::device_session::{NONCE_LEN, NONCE_SECONDS, wallet_login_message, wallet_message};
use crate::wallet_session_anchors::{Anchor, Anchors};
use ed25519_dalek::{Signature, VerifyingKey};

/// A family renews only when its newest generation has at most this much time left (or is
/// gone), so one K holds at most two live generations per family.
pub const RENEW_WINDOW_SECONDS: u64 = 300;
/// Bound on pending renewal nonces held by one Auth.
const CAPACITY: usize = 100_000;

#[derive(Default)]
pub(crate) struct Renewals {
    nonces: HashMap<[u8; NONCE_LEN], u64>,
    pub(super) anchors: Anchors,
}

impl Renewals {
    pub(super) fn prune(&mut self, now: u64) {
        self.nonces
            .retain(|_, issued| now < issued.saturating_add(NONCE_SECONDS));
    }
    /// The anchor of `family`, when it is exactly (member, K).
    pub(super) async fn anchored(
        &self,
        member: Uuid,
        device_key: [u8; 32],
        family: &[u8; 32],
    ) -> Result<Option<Anchor>> {
        Ok(self
            .anchors
            .get(family)
            .await?
            .filter(|anchor| anchor.member == member && anchor.device_key == device_key))
    }
}

/// `Unauthorized` unless `signature` is K's strict Ed25519 signature over `message`.
fn verify(device_key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(device_key).map_err(|_| Error::Unauthorized)?;
    if key.is_weak() {
        return Err(Error::Unauthorized);
    }
    let signature = Signature::from_slice(signature).map_err(|_| Error::Unauthorized)?;
    key.verify_strict(message, &signature)
        .map_err(|_| Error::Unauthorized)
}

impl Auth {
    /// The wallet host's durable anchors (A13 M1): a restart never ends a renewal chain. Every
    /// other host keeps none.
    pub fn with_wallet_anchors(mut self, store: crlt::Community) -> Self {
        self.renewals.anchors = Anchors::durable(store);
        self
    }

    /// Anchor the family of the live passkey session `token` to the wallet device key K (M2:
    /// called inside the passkey login once K's possession is proven, or at a device bind on a
    /// passkey session). Returns the family.
    pub(crate) async fn anchor_wallet_device(
        &mut self,
        token: &str,
        device_key: [u8; 32],
        now: u64,
    ) -> Result<[u8; 32]> {
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
        self.renewals
            .anchors
            .insert(
                family,
                &Anchor {
                    community,
                    member: grant.user,
                    credential: grant.credential,
                    device_key,
                    anchored_at: now,
                },
            )
            .await?;
        Ok(family)
    }

    /// M2: the K proof of the passkey login that opened `token`. A valid proof whose K is C's
    /// current binding (`bound`) anchors the login's family and returns it; an unbound K
    /// anchors nothing. An invalid proof is `Unauthorized`. After a valid proof the passkey
    /// login stands: a binding read or anchor write that fails only leaves the family unanchored
    /// (no renewal, so at most one later prompt), never a refused ceremony.
    pub(super) async fn anchor_login(
        &mut self,
        token: &str,
        host: &str,
        ceremony: &str,
        proof: WalletDeviceProof,
        now: u64,
        bound: impl AsyncFnOnce(Uuid, ckyh::CredentialID, [u8; 32]) -> Result<bool>,
    ) -> Result<Option<[u8; 32]>> {
        let grant = self
            .sessions
            .get(token)
            .map(|session| session.grant.clone())
            .ok_or(Error::Unauthorized)?;
        verify(
            &proof.device_key,
            &wallet_login_message(host, ceremony),
            &proof.signature,
        )?;
        if !matches!(
            bound(grant.user, grant.credential, proof.device_key).await,
            Ok(true)
        ) {
            return Ok(None);
        }
        Ok(self
            .anchor_wallet_device(token, proof.device_key, now)
            .await
            .ok())
    }

    /// End every family in `families` (their anchors are already gone).
    fn end_families(&mut self, families: &[[u8; 32]]) {
        self.sessions
            .retain(|_, session| !families.contains(&session.family));
        self.retain_live();
    }

    /// Revoke K for `member`: every family anchored to it ends now and can never renew.
    pub(crate) async fn revoke_wallet_device(
        &mut self,
        member: Uuid,
        device_key: [u8; 32],
    ) -> Result<()> {
        let families = self
            .renewals
            .anchors
            .forget_where(member, |_, key| *key == device_key)
            .await?;
        self.end_families(&families);
        Ok(())
    }

    /// Passkey C revoked: every family anchored through C ends now.
    pub(crate) async fn revoke_wallet_credential(
        &mut self,
        member: Uuid,
        credential: &ckyh::CredentialID,
    ) -> Result<()> {
        let families = self
            .renewals
            .anchors
            .forget_where(member, |anchored, _| anchored == credential.as_ref())
            .await?;
        self.end_families(&families);
        Ok(())
    }

    /// C rebound to `device_key`: the families anchored to C's previous keys end now.
    pub(crate) async fn rebind_wallet_device(
        &mut self,
        member: Uuid,
        credential: &ckyh::CredentialID,
        device_key: [u8; 32],
    ) -> Result<()> {
        let families = self
            .renewals
            .anchors
            .forget_where(member, |anchored, key| {
                anchored == credential.as_ref() && *key != device_key
            })
            .await?;
        self.end_families(&families);
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
    /// binding check (M4): K must still be C's bound device key of an eligible account. It runs
    /// only after the nonce, the signature and the anchor have been checked.
    pub async fn wallet_renew(
        &mut self,
        host: &str,
        request: WalletSessionRenew,
        now: u64,
        bound: impl AsyncFnOnce(Uuid, ckyh::CredentialID, [u8; 32]) -> Result<bool>,
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
        verify(
            &request.device_key,
            &wallet_message(
                host,
                user.as_bytes(),
                &request.family,
                &request.nonce,
                issued,
            ),
            &request.signature,
        )?;
        // M1: an anchor of exactly this member, K and family.
        let anchor = self
            .renewals
            .anchored(user, request.device_key, &request.family)
            .await?
            .ok_or(Error::Unauthorized)?;
        // M4: K is still C's current binding (and the account is not burned).
        if !bound(user, anchor.credential.clone(), request.device_key).await? {
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
        .map_err(Error::Unavailable.redact())?
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
            family: Some(request.family),
        })
    }
}
