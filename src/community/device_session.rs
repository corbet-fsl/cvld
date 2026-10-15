//! Sessions opened by a registered device key, without any passkey prompt. The server issues a
//! one-use nonce; the device signs it; the key must be ACTIVE for that member in this community.
//! Renewal is the same exchange. Every refusal after the nonce lookup is the same `Unauthorized`.
use super::*;
use crate::device_session::{
    JOIN_ACTION, NONCE_LEN, NONCE_SECONDS, UNFOUNDED_FINGERPRINT_TAG, join_message, join_payload,
    message,
};
use ed25519_dalek::{Signature, VerifyingKey};

/// Default rulebook stamp cohort: one UTC day (decided 2026-10-15).
pub const DEFAULT_STAMP_COHORT_SECONDS: u64 = 86_400;

impl CommunityService {
    pub async fn device_session_begin(&mut self, now: u64) -> Result<DeviceSessionChallenge> {
        self.prune(now);
        if self.device_nonces.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        let nonce: [u8; NONCE_LEN] = rand::random();
        crate::service::publication::expires_at(now + NONCE_SECONDS)?;
        self.device_nonces.insert(nonce, now);
        Ok(DeviceSessionChallenge { nonce, issued: now })
    }

    pub async fn device_session_finish(
        &mut self,
        request: DeviceSessionFinish,
        now: u64,
    ) -> Result<Session> {
        self.prune(now);
        if self.sessions.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        // Single use: the nonce is spent whatever follows.
        let issued = self
            .device_nonces
            .remove(&request.nonce)
            .ok_or(Error::Unauthorized)?;
        if now < issued || now >= issued.saturating_add(NONCE_SECONDS) {
            return Err(Error::Unauthorized);
        }
        let key =
            VerifyingKey::from_bytes(&request.device_key).map_err(Error::Unauthorized.redact())?;
        let signature =
            Signature::from_slice(&request.signature).map_err(Error::Unauthorized.redact())?;
        key.verify_strict(
            &message(&self.config.community, &request.nonce, issued),
            &signature,
        )
        .map_err(Error::Unauthorized.redact())?;
        let user = ckyh::Uuid::parse_str(&request.user).map_err(Error::Unauthorized.redact())?;
        let member = user.to_string();
        // The membership checks that the key is ACTIVE for this member in this community and
        // that the member is live and unrestricted; it rechecks both on every request.
        let authentication = Arc::new(ckyh::Authentication::from_device_key(
            self.config.community.clone(),
            user,
            request.device_key,
        ));
        if !self
            .facade
            .membership()
            .device_session_is_active(&authentication)
            .await
            .map_err(Error::Unauthorized.redact())?
        {
            return Err(Error::Unauthorized);
        }
        let expires = now
            .checked_add(self.config.session_seconds)
            .ok_or(Error::Invalid)?;
        crate::service::publication::expires_at(expires)?;
        let id = token();
        // A full member session: the same state a passkey login creates, with another origin.
        self.sessions.insert(
            id.clone(),
            SessionState {
                authentication: authentication.clone(),
                authority: session_authority::Owner::default(),
                garden: false,
                started: now,
                grant: Grant {
                    user,
                    role: Role::Member,
                    expires,
                    credential: authentication.credential_id().clone(),
                    origin: ckyh::Origin::DeviceKey,
                    session_id: rand::random(),
                },
            },
        );
        Ok(Session {
            token: id,
            user: member,
            role: Role::Member,
            expires,
        })
    }

    /// JOIN by device key: one passport presentation over this community's challenge, one
    /// confirmation stamp covering `device_join` of exactly this key under the same pseudonym,
    /// and the key's signature over the join message. The digest is recorded once; a retry of
    /// the same join (same digest, same key) returns the same member.
    pub async fn device_join(&mut self, request: DeviceJoin, now: u64) -> Result<DeviceJoined> {
        self.refresh_global(now).await?;
        self.prune(now);
        let input = request.passport;
        let challenge = self
            .challenges
            .remove(&input.challenge)
            .ok_or(Error::Refused)?;
        crate::service::publication::expires_at(challenge.until)?;
        if challenge.owner.is_some() || challenge.value.root_board_request().is_some() {
            return Err(Error::Forbidden);
        }
        if request.seed == [0; 32] {
            return Err(Error::Invalid);
        }
        if request.seed == [0; 32] {
            return Err(Error::Invalid);
        }
        let key =
            VerifyingKey::from_bytes(&request.device_key).map_err(Error::Unauthorized.redact())?;
        if key.is_weak() {
            return Err(Error::Unauthorized);
        }
        let signature =
            Signature::from_slice(&request.signature).map_err(Error::Unauthorized.redact())?;
        key.verify_strict(
            &join_message(
                &self.config.community,
                &input.challenge,
                &request.device_key,
            ),
            &signature,
        )
        .map_err(Error::Unauthorized.redact())?;
        let proof =
            cpsd::Presentation::from_bytes(&input.proof).map_err(Error::Invalid.redact())?;
        let passport = self
            .facade
            .verify(&mut cpsd::rand::rngs::OsRng, &challenge.value, &proof, now)
            .await
            .map_err(Error::Refused.redact())?;
        let global = crate::global_trust::load(&self.db, &self.config, now).await?;
        let stamp_key = cpsd::StampPublicKey::from_bytes(
            global
                .status
                .stamp_public_key
                .as_deref()
                .ok_or(Error::Refused)?,
        )
        .map_err(Error::Refused.redact())?;
        let params = cpsd::StampParams::new(
            self.config
                .stamp_cohort_seconds
                .unwrap_or(DEFAULT_STAMP_COHORT_SECONDS),
        )
        .map_err(Error::Invalid.redact())?;
        let ledger = cpsd::StampLedger::new(
            crate::stamp_uses::StampUses::new(
                &self.db,
                &self.config.community,
                crate::stamp_uses::DEFAULT_CAPACITY,
            )?,
            self.stamp_fingerprint(),
            vec![stamp_key.clone()],
            params,
        )
        .map_err(Error::Refused.redact())?;
        let action = cpsd::StampAction::new(
            cpsd::ActionKind::new(JOIN_ACTION).map_err(Error::Invalid.redact())?,
            cpsd::PayloadDigest::from_bytes(join_payload(&request.device_key, &request.seed)),
            cpsd::StampSalt::from_bytes(request.salt),
        );
        let presentation =
            cpsd::StampPresentation::from_bytes(&request.stamp).map_err(Error::Invalid.redact())?;
        let verified = cpsd::verify_stamp(
            &[stamp_key],
            &params,
            &ledger.scope(),
            global.status.epoch,
            &action,
            &presentation,
            now,
        )
        .map_err(Error::Refused.redact())?;
        if verified.pseudonym().to_hex() != passport.member_id() {
            return Err(Error::Refused);
        }
        ledger
            .prune(now)
            .await
            .map_err(Error::Unavailable.redact())?;
        // One use per digest; the same digest is the same join, which is idempotent below.
        let fresh = match ledger.record(&verified, now).await {
            Ok(()) => true,
            Err(cpsd::Error::StampReplayed) => false,
            Err(_) => return Err(Error::Unavailable),
        };
        match self
            .facade
            .join_with_device_key(
                passport,
                ckyh::Uuid::new_v4(),
                request.device_key,
                request.seed,
                now,
            )
            .await
        {
            Ok(record) => Ok(DeviceJoined {
                user: record.user().to_string(),
            }),
            Err(_) => {
                if fresh {
                    // Not applied: free the digest so the member can retry with this stamp.
                    let _ = ledger.release(&verified, now).await;
                }
                Err(Error::Refused)
            }
        }
    }

    /// The community fingerprint stamp digests bind to: SHA-256 of the founding document, or
    /// for a community without one, SHA-256 of a domain tag and the community id.
    fn stamp_fingerprint(&self) -> cpsd::CommunityFingerprint {
        use sha2::Digest as _;
        let digest = match &self.genesis {
            Some(genesis) => sha2::Sha256::digest(genesis),
            None => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(UNFOUNDED_FINGERPRINT_TAG);
                hasher.update(self.config.community.as_bytes());
                hasher.finalize()
            }
        };
        cpsd::CommunityFingerprint::from_bytes(digest.into())
    }
}
