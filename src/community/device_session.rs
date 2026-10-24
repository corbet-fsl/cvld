//! Sessions opened by a registered device key, without any passkey prompt. The server issues a
//! one-use nonce; the device signs it; the key must be ACTIVE for that member in this community.
//! Renewal is the same exchange. Every refusal after the nonce lookup is the same `Unauthorized`.
use super::*;
use crate::device_session::{
    ACTIVATE_ACTION, ADD_ACTION, JOIN_ACTION, NONCE_LEN, NONCE_SECONDS, join_message, join_payload,
    message, pairing_payload,
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
        let key = VerifyingKey::from_bytes(&request.device_key)
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:1"))?;
        let signature = Signature::from_slice(&request.signature)
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:2"))?;
        key.verify_strict(
            &message(&self.config.community, &request.nonce, issued),
            &signature,
        )
        .map_err(Error::Unauthorized.redact_at("community/device_session.rs:3"))?;
        let user = ckyh::Uuid::parse_str(&request.user)
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:4"))?;
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
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:5"))?
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
                    // Community sessions never carry the wallet birth grant.
                    uv_at: None,
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

    /// Open an ADMIN session by a registered device key and one confirmation stamp (the step-up
    /// of the admin portal: no community passkey). The key's member must hold the Admin or Root
    /// role now; the stamp must verify under this community's scope for exactly this key and
    /// nonce and belong to that member's pseudonym. Every refusal is the same `Unauthorized`
    /// once the nonce is spent; the role is rechecked on every request by the garden path.
    pub async fn garden_session_finish(
        &mut self,
        request: GardenSessionFinish,
        now: u64,
    ) -> Result<Session> {
        self.prune(now);
        if self.sessions.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        let issued = self
            .device_nonces
            .remove(&request.nonce)
            .ok_or(Error::Unauthorized)?;
        if now < issued || now >= issued.saturating_add(NONCE_SECONDS) {
            return Err(Error::Unauthorized);
        }
        let key = VerifyingKey::from_bytes(&request.device_key)
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:6"))?;
        let signature = Signature::from_slice(&request.signature)
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:7"))?;
        key.verify_strict(
            &crate::device_session::garden_message(&self.config.community, &request.nonce, issued),
            &signature,
        )
        .map_err(Error::Unauthorized.redact_at("community/device_session.rs:8"))?;
        let user = ckyh::Uuid::parse_str(&request.user)
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:9"))?;
        let authentication = Arc::new(ckyh::Authentication::from_device_key(
            self.config.community.clone(),
            user,
            request.device_key,
        ));
        let expires = now
            .checked_add(self.config.session_seconds)
            .ok_or(Error::Invalid)?;
        crate::service::publication::expires_at(expires)?;
        // Key active and member live, and the role is Admin or Root right now.
        let lease = self
            .garden_lease(&authentication, now, expires)
            .await
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:10"))?;
        // One confirmation stamp over this key and nonce, from this member's own pseudonym.
        let global = crate::global_trust::load(&self.db, &self.config, now).await?;
        let stamp_key = cpsd::StampPublicKey::from_bytes(
            global
                .status
                .stamp_public_key
                .as_deref()
                .ok_or(Error::Unauthorized)?,
        )
        .map_err(Error::Unauthorized.redact_at("community/device_session.rs:11"))?;
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
            *self.stamp_scope()?.fingerprint(),
            vec![stamp_key.clone()],
            params,
        )
        .map_err(Error::Unauthorized.redact_at("community/device_session.rs:12"))?;
        let action = cpsd::StampAction::new(
            cpsd::ActionKind::new(crate::device_session::GARDEN_ACTION)
                .map_err(Error::Invalid.redact())?,
            cpsd::PayloadDigest::from_bytes(crate::device_session::garden_payload(
                &request.device_key,
                &request.nonce,
            )),
            cpsd::StampSalt::from_bytes(request.salt),
        );
        let verified = cpsd::StampPresentation::from_bytes(&request.stamp)
            .ok()
            .and_then(|presentation| {
                cpsd::verify_stamp(
                    &[stamp_key],
                    &params,
                    &ledger.scope(),
                    global.status.epoch,
                    &action,
                    &presentation,
                    now,
                )
                .ok()
            })
            .ok_or(Error::Unauthorized)?;
        if verified.pseudonym().to_hex() != lease.member() {
            return Err(Error::Unauthorized);
        }
        ledger
            .prune(now)
            .await
            .map_err(Error::Unavailable.redact_at("community/device_session.rs:13"))?;
        // A stamp covers one attempt: a replay is refused.
        ledger
            .record(&verified, now)
            .await
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:14"))?;
        let role = garden::public_role(lease.role());
        let expires = expires.min(lease.valid_until());
        let id = token();
        self.sessions.insert(
            id.clone(),
            SessionState {
                authentication: authentication.clone(),
                authority: session_authority::Owner::default(),
                garden: true,
                started: now,
                grant: Grant {
                    user,
                    role,
                    expires,
                    credential: authentication.credential_id().clone(),
                    origin: ckyh::Origin::DeviceKey,
                    session_id: rand::random(),
                    // Admin (garden) sessions never carry the wallet birth grant.
                    uv_at: None,
                },
            },
        );
        drop(lease);
        Ok(Session {
            token: id,
            user: request.user,
            role,
            expires,
        })
    }

    /// JOIN by device key: one passport presentation over this community's challenge, one
    /// confirmation stamp covering `device_join` of exactly this key under the same pseudonym,
    /// and the key's signature over the join message. The digest is recorded once; a retry of
    /// the same join (same digest, same key) returns the same member, also after the stamp
    /// expired (re-confirmed from the applied state, see below).
    pub async fn device_join(&mut self, request: DeviceJoin, now: u64) -> Result<DeviceJoined> {
        self.refresh_global(now).await?;
        self.prune(now);
        let input = request.passport;
        let challenge = self.challenges.remove(&input.challenge).ok_or_else(|| {
            Error::Refused.noted("community/device_session.rs:join-challenge-missing")
        })?;
        crate::service::publication::expires_at(challenge.until)
            .map_err(|e| e.noted("community/device_session.rs:join-publication-deadline"))?;
        if challenge.owner.is_some() || challenge.value.root_board_request().is_some() {
            return Err(Error::Forbidden);
        }
        if request.seed == [0; 32] {
            return Err(Error::Invalid);
        }
        let key = VerifyingKey::from_bytes(&request.device_key)
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:15"))?;
        if key.is_weak() {
            return Err(Error::Unauthorized);
        }
        let signature = Signature::from_slice(&request.signature)
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:16"))?;
        key.verify_strict(
            &join_message(
                &self.config.community,
                &input.challenge,
                &request.device_key,
            ),
            &signature,
        )
        .map_err(Error::Unauthorized.redact_at("community/device_session.rs:17"))?;
        let proof =
            cpsd::Presentation::from_bytes(&input.proof).map_err(Error::Invalid.redact())?;
        let passport = self
            .facade
            .verify(&mut cpsd::rand::rngs::OsRng, &challenge.value, &proof, now)
            .await
            .map_err(Error::Refused.redact_at("community/device_session.rs:18"))?;
        let global = crate::global_trust::load(&self.db, &self.config, now).await?;
        let stamp_key = cpsd::StampPublicKey::from_bytes(
            global.status.stamp_public_key.as_deref().ok_or_else(|| {
                Error::Refused.noted("community/device_session.rs:join-no-stamp-key")
            })?,
        )
        .map_err(Error::Refused.redact_at("community/device_session.rs:19"))?;
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
            *self.stamp_scope()?.fingerprint(),
            vec![stamp_key.clone()],
            params,
        )
        .map_err(Error::Refused.redact_at("community/device_session.rs:20"))?;
        let action = cpsd::StampAction::new(
            cpsd::ActionKind::new(JOIN_ACTION).map_err(Error::Invalid.redact())?,
            cpsd::PayloadDigest::from_bytes(join_payload(&request.device_key, &request.seed)),
            cpsd::StampSalt::from_bytes(request.salt),
        );
        let verified = cpsd::StampPresentation::from_bytes(&request.stamp)
            .ok()
            .and_then(|presentation| {
                cpsd::verify_stamp(
                    &[stamp_key],
                    &params,
                    &ledger.scope(),
                    global.status.epoch,
                    &action,
                    &presentation,
                    now,
                )
                .map_err(Error::Refused.redact_at("community/device_session.rs:join-verify-stamp"))
                .ok()
            });
        let Some(verified) = verified else {
            // No stamp that verifies now (its cohort ended, or none was sent): only the SAME
            // join, already applied, is re-confirmed: this passport's member holds exactly
            // this key with exactly this seed. Nothing changes and no digest is recorded, so
            // a device interrupted after its join was applied never needs a second
            // confirmation. Anything else needs a fresh stamp.
            return match self
                .facade
                .device_join_applied(passport, request.device_key, request.seed, now)
                .await
            {
                Ok(Some(record)) => Ok(DeviceJoined {
                    user: record.user().to_string(),
                }),
                _ => Err(Error::Refused
                    .noted("community/device_session.rs:join-no-valid-stamp-not-applied")),
            };
        };
        if verified.pseudonym().to_hex() != passport.member_id() {
            return Err(
                Error::Refused.noted("community/device_session.rs:join-stamp-pseudonym-mismatch")
            );
        }
        ledger
            .prune(now)
            .await
            .map_err(Error::Unavailable.redact_at("community/device_session.rs:21"))?;
        // One use per digest; the same digest is the same join, which is idempotent below.
        let fresh = match ledger.record(&verified, now).await {
            Ok(()) => true,
            Err(cpsd::Error::StampReplayed) => false,
            Err(_) => {
                return Err(
                    Error::Unavailable.noted("community/device_session.rs:join-stamp-record")
                );
            }
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

    /// One stamped pairing step (`device_add` registers the key PENDING, `device_activate`
    /// makes it ACTIVE): the same checks as a join (one-use challenge, key signature, passport,
    /// stamp covering exactly this action and key under the passport's pseudonym), but a stamp
    /// that no longer verifies is always refused. The digest is recorded once; a retry with the
    /// same stamp is idempotent in the membership, and a failed apply frees the digest.
    pub async fn device_pairing(
        &mut self,
        kind: &'static str,
        request: DevicePairing,
        now: u64,
    ) -> Result<Empty> {
        debug_assert!(kind == ADD_ACTION || kind == ACTIVATE_ACTION);
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
        let key = VerifyingKey::from_bytes(&request.device_key)
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:22"))?;
        if key.is_weak() {
            return Err(Error::Unauthorized);
        }
        let signature = Signature::from_slice(&request.signature)
            .map_err(Error::Unauthorized.redact_at("community/device_session.rs:23"))?;
        key.verify_strict(
            &join_message(
                &self.config.community,
                &input.challenge,
                &request.device_key,
            ),
            &signature,
        )
        .map_err(Error::Unauthorized.redact_at("community/device_session.rs:24"))?;
        let proof =
            cpsd::Presentation::from_bytes(&input.proof).map_err(Error::Invalid.redact())?;
        let passport = self
            .facade
            .verify(&mut cpsd::rand::rngs::OsRng, &challenge.value, &proof, now)
            .await
            .map_err(Error::Refused.redact_at("community/device_session.rs:25"))?;
        let global = crate::global_trust::load(&self.db, &self.config, now).await?;
        let stamp_key = cpsd::StampPublicKey::from_bytes(
            global
                .status
                .stamp_public_key
                .as_deref()
                .ok_or(Error::Refused)?,
        )
        .map_err(Error::Refused.redact_at("community/device_session.rs:26"))?;
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
            *self.stamp_scope()?.fingerprint(),
            vec![stamp_key.clone()],
            params,
        )
        .map_err(Error::Refused.redact_at("community/device_session.rs:27"))?;
        let action = cpsd::StampAction::new(
            cpsd::ActionKind::new(kind).map_err(Error::Invalid.redact())?,
            cpsd::PayloadDigest::from_bytes(pairing_payload(kind, &request.device_key)),
            cpsd::StampSalt::from_bytes(request.salt),
        );
        let verified = cpsd::StampPresentation::from_bytes(&request.stamp)
            .map_err(Error::Refused.redact_at("community/device_session.rs:28"))
            .and_then(|presentation| {
                cpsd::verify_stamp(
                    &[stamp_key],
                    &params,
                    &ledger.scope(),
                    global.status.epoch,
                    &action,
                    &presentation,
                    now,
                )
                .map_err(Error::Refused.redact_at("community/device_session.rs:29"))
            })?;
        if verified.pseudonym().to_hex() != passport.member_id() {
            return Err(Error::Refused);
        }
        ledger
            .prune(now)
            .await
            .map_err(Error::Unavailable.redact_at("community/device_session.rs:30"))?;
        let fresh = match ledger.record(&verified, now).await {
            Ok(()) => true,
            Err(cpsd::Error::StampReplayed) => false,
            Err(_) => return Err(Error::Unavailable),
        };
        let applied = if kind == ADD_ACTION {
            self.facade
                .add_device_key(passport, request.device_key, now)
                .await
        } else {
            self.facade
                .activate_device_key(passport, request.device_key, now)
                .await
        };
        match applied {
            Ok(()) => Ok(Empty {}),
            Err(_) => {
                if fresh {
                    let _ = ledger.release(&verified, now).await;
                }
                Err(Error::Refused)
            }
        }
    }

    /// The stamp scope of this community (`cpsd::StampScope::of_community`): the
    /// `csgn::community_fingerprint` of the founding document's key, or for a community
    /// without one, of its id alone. Devices build it the same way from the verified Charter.
    fn stamp_scope(&self) -> Result<cpsd::StampScope> {
        let founding = self.founding_fingerprint()?;
        let id = cpsd::CommunityId::new(&self.config.community).map_err(Error::Invalid.redact())?;
        Ok(cpsd::StampScope::of_community(id, founding.as_ref()))
    }

    /// The founding key fingerprint of this community's verified genesis, if it has one.
    fn founding_fingerprint(&self) -> Result<Option<[u8; 32]>> {
        match self.genesis.as_deref() {
            Some(genesis) => Ok(Some(
                csgn::verify_genesis(genesis)
                    .map_err(Error::Unavailable.redact_at("community/device_session.rs:31"))?
                    .fingerprint(),
            )),
            None => Ok(None),
        }
    }

    /// The genesis stamp check of a device-key member's FIRST publication bind. The member's
    /// first lineage needs no community passkey: the bind carries `cchr::genesis_stamp`
    /// evidence whose receipt is this member's first `Created` lineage in this community,
    /// authored by the session's device key, stamped under the member's pseudonym at the
    /// current global epoch with a key of the signed stamp ring valid at the receipt time.
    /// The stamp digest is recorded once in `cvld_stamp_uses` and retained `pending_days` past
    /// the stamp, so it outlives the member's registration deadline (a member past it cannot
    /// bind at all). A passkey session must not send
    /// evidence. An equal retry of an already bound publication is not re-verified (its stamp
    /// may have expired since); a different winner is refused by the membership's CAS. After
    /// the stamp expired, only the idempotent re-confirm of the SAME already recorded pending
    /// genesis (same digest) is accepted; an expired stamp never starts a new genesis.
    pub(super) async fn device_genesis_stamp(
        &self,
        authentication: &ckyh::Authentication,
        bind: &InitialPublicationBind,
        expires_at: i64,
        now: u64,
    ) -> Result<Option<GenesisStampUse>> {
        let Some(device_key) = authentication.device_key() else {
            return match bind.evidence {
                Some(_) => Err(Error::Invalid),
                None => Ok(None),
            };
        };
        let evidence = bind.evidence.as_deref().ok_or(Error::Invalid)?;
        let membership = self.facade.membership();
        let bound = membership
            .initial_creation(authentication, expires_at)
            .await
            .map_err(|error| match error {
                cmbr::Error::Unavailable => Error::Unavailable,
                _ => Error::Refused,
            })?
            .publication();
        if bound.is_some() {
            return Ok(None);
        }
        let genesis =
            cchr::GenesisStampEvidence::from_bytes(evidence).map_err(Error::Invalid.redact())?;
        let member = membership
            .resume(authentication)
            .await
            .map_err(Error::Refused.redact_at("community/device_session.rs:32"))?
            .subject()
            .to_owned();
        let global = crate::global_trust::load(&self.db, &self.config, now).await?;
        let params = cpsd::StampParams::new(
            self.config
                .stamp_cohort_seconds
                .unwrap_or(DEFAULT_STAMP_COHORT_SECONDS),
        )
        .map_err(Error::Invalid.redact())?;
        let (keys, trust) = stamp_trust(&global.status, params)?;
        let founding = self.founding_fingerprint()?;
        let verified = cchr::verify_genesis_parts(
            &self.config.community,
            founding.as_ref(),
            &trust,
            &genesis,
            &member,
            now,
        )
        .map_err(Error::Refused.redact_at("community/device_session.rs:33"))?;
        // The receipt's author is the session's device key (VLD0 = Ed25519).
        let author = verified.author();
        if author.kind().bytes() != b"VLD0"
            || author.value() != &device_key
            || verified.stamp().epoch() != global.status.epoch
        {
            return Err(Error::Refused);
        }
        let stamp = verified.into_stamp();
        let ledger = cpsd::StampLedger::new(
            crate::stamp_uses::StampUses::new(
                &self.db,
                &self.config.community,
                crate::stamp_uses::DEFAULT_CAPACITY,
            )?
            .retaining(u64::from(self.config.pending_days) * 86_400),
            *self.stamp_scope()?.fingerprint(),
            keys.into_iter()
                .filter(|key| key.params() == params)
                .collect(),
            params,
        )
        .map_err(Error::Refused.redact_at("community/device_session.rs:34"))?;
        ledger
            .prune(now)
            .await
            .map_err(Error::Unavailable.redact_at("community/device_session.rs:35"))?;
        // One use per digest. The same digest is the same member's same genesis: a retry
        // after an attempt whose bind failed or whose outcome is unknown.
        let fresh = match ledger.record(&stamp, now).await {
            Ok(()) => true,
            Err(cpsd::Error::StampReplayed) => false,
            // Expired: only the re-confirm of the same recorded pending genesis.
            Err(cpsd::Error::StampExpired) => match ledger.recorded(&stamp, now).await {
                Ok(true) => false,
                Ok(false) => return Err(Error::Refused),
                Err(_) => return Err(Error::Unavailable),
            },
            Err(_) => return Err(Error::Unavailable),
        };
        Ok(Some(GenesisStampUse {
            ledger,
            stamp,
            fresh,
        }))
    }
}

/// A genesis stamp digest recorded for one publication bind.
pub(super) struct GenesisStampUse {
    ledger: cpsd::StampLedger<crate::stamp_uses::StampUses>,
    stamp: cpsd::VerifiedStamp,
    fresh: bool,
}
impl GenesisStampUse {
    /// The bind was definitively NOT applied: free a digest this bind recorded, so the member
    /// can retry with the same stamp. Never for an applied or possibly applied bind.
    pub(super) async fn release(self, now: u64) {
        if self.fresh {
            let _ = self.ledger.release(&self.stamp, now).await;
        }
    }
}

/// The wallet's stamp key ring from its signed global status: every recorded key with its
/// period, or (before rings were recorded) the current key alone, valid from the start.
fn stamp_trust(
    status: &cgbl::Status,
    params: cpsd::StampParams,
) -> Result<(Vec<cpsd::StampPublicKey>, cchr::StampTrust)> {
    let key = |bytes: &[u8]| {
        cpsd::StampPublicKey::from_bytes(bytes)
            .map_err(Error::Refused.redact_at("community/device_session.rs:36"))
    };
    let ring = if status.stamp_keys.is_empty() {
        vec![(
            key(status.stamp_public_key.as_deref().ok_or(Error::Refused)?)?,
            0,
            None,
        )]
    } else {
        status
            .stamp_keys
            .iter()
            .map(|period| {
                Ok((
                    key(&period.public_key)?,
                    period.valid_from,
                    period.valid_until,
                ))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let periods = ring
        .iter()
        .map(|(key, from, until)| {
            cchr::StampKeyPeriod::new(key.clone(), *from, *until)
                .map_err(Error::Refused.redact_at("community/device_session.rs:37"))
        })
        .collect::<Result<Vec<_>>>()?;
    let trust = cchr::StampTrust::new(periods, params)
        .map_err(Error::Refused.redact_at("community/device_session.rs:38"))?;
    Ok((ring.into_iter().map(|(key, _, _)| key).collect(), trust))
}
