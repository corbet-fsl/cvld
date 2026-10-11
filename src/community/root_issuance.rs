//! Actual source garden sessions joined to the in-process ROOT purpose owner.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub(crate) type Issuer = cmty::RootBoardIssuer<
    cpsd::storage::libsql::LibsqlStore,
    Rules,
    cplc::LibsqlStore,
    csgn::LibsqlStore,
>;

pub(super) struct PendingRootIssuance {
    value: cmty::RootBoardChallenge,
    pub(super) session_id: [u8; 32],
    credential: ckyh::CredentialID,
    pub(super) until: u64,
}

impl CommunityService {
    pub(crate) async fn begin_root_issuance(
        &mut self,
        bearer: &str,
        admitted_at: u64,
    ) -> Result<RootBoardIssueChallenge> {
        let purpose = self.root_purpose.clone().ok_or(Error::Unavailable)?;
        let source_clock = self.clock.clone();
        let clock = JointClock::new(source_clock, &purpose, admitted_at);
        let now = clock.check(u64::MAX)?;
        self.prune(now);
        if self.root_issuances.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        let (grant, auth) = self.authenticate_garden_current(bearer, now).await?;
        let now = clock.check(grant.expires)?;
        self.refresh_global(now).await?;
        clock.check(grant.expires)?;
        let session = cmty::RootBoardSession {
            authentication: &auth,
            valid_until: grant.expires,
            clock: || clock.now(),
        };
        let value = self
            .facade
            .begin_root_board_issuance(&purpose.issuer, &mut cpsd::rand::rngs::OsRng, &session)
            .await
            .map_err(Error::Refused.redact())?;
        let until = value.valid_until().min(grant.expires);
        self.check_root_session(bearer, &grant, &auth, clock.check(until)?)?;
        crate::service::publication::expires_at(until)?;
        let challenge = token();
        let response = RootBoardIssueChallenge {
            challenge: challenge.clone(),
            signed_context: value.signed_context().to_vec(),
            signed_source_request: value.signed_source_request().to_vec(),
            expires: until,
        };
        self.root_issuances.insert(
            challenge,
            PendingRootIssuance {
                value,
                session_id: grant.session_id,
                credential: grant.credential,
                until,
            },
        );
        Ok(response)
    }

    pub(crate) async fn finish_root_issuance(
        &mut self,
        bearer: &str,
        request: RootBoardIssueFinish,
        admitted_at: u64,
    ) -> Result<Bytes> {
        let purpose = self.root_purpose.clone().ok_or(Error::Unavailable)?;
        let clock = JointClock::new(self.clock.clone(), &purpose, admitted_at);
        let (grant, auth) = self
            .authenticate_garden_current(bearer, clock.check(u64::MAX)?)
            .await?;
        let pending = self
            .root_issuances
            .get(&request.challenge)
            .ok_or(Error::Unauthorized)?;
        if pending.session_id != grant.session_id || pending.credential != grant.credential {
            return Err(Error::Unauthorized);
        }
        let until = pending.until.min(grant.expires);
        crate::service::publication::expires_at(until)?;
        clock.check(until)?;
        let proof = cpsd::RootBoardIssuanceRequest::from_bytes(&request.proof)
            .map_err(Error::Invalid.redact())?;
        // Remove before any awaited proof/consume work. On loss/cancellation the
        // holder starts a fresh context; neither nonce nor response is restored.
        let pending = self
            .root_issuances
            .remove(&request.challenge)
            .ok_or(Error::Unauthorized)?;
        let now = clock.check(until)?;
        self.refresh_global(now).await?;
        clock.check(until)?;
        let session = cmty::RootBoardSession {
            authentication: &auth,
            valid_until: grant.expires,
            clock: || clock.now(),
        };
        let answer = self
            .facade
            .finish_root_board_issuance(
                &purpose.issuer,
                &mut cpsd::rand::rngs::OsRng,
                &session,
                &pending.value,
                &proof,
            )
            .await
            .map_err(|error| match error {
                cmty::Error::Reconcile => Error::Reconcile,
                _ => Error::Refused,
            })?;
        let released_at = clock.floor.load(Ordering::SeqCst);
        let bytes = answer.to_bytes();
        // The caller still holds this CommunityService mutex, including the
        // actual sessions map. No session mutation can race this synchronous
        // identity/time check; CMTY just checked real role/key/legal owners.
        let completed = clock.check(until).and_then(|now| {
            if now != released_at {
                return Err(Error::Reconcile);
            }
            self.check_root_session(bearer, &grant, &auth, now)
        });
        completed.map_err(|_| Error::Reconcile)?;
        Ok(Bytes { bytes })
    }

    fn check_root_session(
        &self,
        bearer: &str,
        expected: &Grant,
        authentication: &Arc<ckyh::Authentication>,
        now: u64,
    ) -> Result<()> {
        let current = self.sessions.get(bearer).ok_or(Error::Unauthorized)?;
        let grant = &current.grant;
        // Garden role and a possibly shorter membership deadline come from the
        // current owner read, not the historical login role. Retain the exact
        // original session identity and never extend its stored expiry.
        if !Arc::ptr_eq(authentication, &current.authentication)
            || grant.user != expected.user
            || grant.session_id != expected.session_id
            || grant.credential != expected.credential
            || expected.expires > grant.expires
            || now >= expected.expires
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

// Preserve EACH owner's direct observation floor, then use the later time for
// shared authority. Taking only max(root, source) would hide one regressing clock.
struct JointClock<'a> {
    source: Arc<dyn Clock>,
    root: &'a crate::service::RootBoardPurpose,
    source_floor: AtomicU64,
    floor: AtomicU64,
    invalid: AtomicBool,
}

impl<'a> JointClock<'a> {
    fn new(source: Arc<dyn Clock>, root: &'a crate::service::RootBoardPurpose, floor: u64) -> Self {
        Self {
            source,
            root,
            source_floor: AtomicU64::new(0),
            floor: AtomicU64::new(floor),
            invalid: AtomicBool::new(false),
        }
    }
    fn now(&self) -> u64 {
        let source = self.source.now();
        let root = self.root.now().unwrap_or(0);
        let now = source.max(root);
        if source == 0
            || root == 0
            || source < self.source_floor.load(Ordering::SeqCst)
            || now < self.floor.load(Ordering::SeqCst)
        {
            self.invalid.store(true, Ordering::SeqCst);
        }
        self.source_floor.fetch_max(source, Ordering::SeqCst);
        self.floor.fetch_max(now, Ordering::SeqCst);
        if self.invalid.load(Ordering::SeqCst) {
            0
        } else {
            now
        }
    }
    fn check(&self, until: u64) -> Result<u64> {
        let now = self.now();
        if now == 0 || now >= until || now >= cpsd::TIME_LIMIT {
            Err(Error::Unauthorized)
        } else {
            Ok(now)
        }
    }
}
