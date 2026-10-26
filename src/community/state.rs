//! Deterministic state-evaluator seam (work package P1).
//!
//! Implements `DESIGN-state-model-2026-10-26.md` §2 (evaluation contract and
//! time) and §3 (base facts). Later `STATUS.md` rows dated 2026-10-26
//! (conversation scale, anchor strengths, outage rule) shape future consumer
//! evaluators, not this seam.
//!
//! Contract: `State = f(facts_at_frontier, checkpoint, policy_version)`.
//! Same inputs give the same answer; different frontiers are explicitly
//! different observations, not drifting flags. An unavailable current frontier
//! refuses the operation; it is not evidence of exclusion.
//!
//! There are no timers, no background jobs, no mutation of stored state and
//! no device clocks in this module. Time is only the signed community tick
//! (`TICK_SECONDS = 15`); every validity interval is half-open `[start, end)`
//! with equality to `end` meaning expired.
//!
//! The checkpoint signer is the community's PUBLISHING key held by the cvld
//! service, never a founder's device key: a founder is mostly offline and
//! cannot sign a tick every 15 s. Authority is the existing per-community
//! publishing key chain (`csgn`): cfrm pins the publishing root key from
//! deployment configuration and every later ring must be signed by the
//! currently installed one (STATUS.md "feed key continuity", 2026-10-01).
//! Checkpoints are accepted only from a key the resolved ring authorizes;
//! ring transitions are walked with `verify_transition_at_issue`, so no clock
//! is needed.
//!
//! Cryptography is reused, not invented: checkpoints and facts are signed
//! with `ed25519_dalek` (the key type already used for listing keys and
//! enrollment operators), ring authority is `csgn`, and digests use
//! `sha2::Sha256` (already used for claim and payload digests).

use csgn::KeyRing;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Community seconds per signed tick (design §2, M choice).
pub const TICK_SECONDS: u64 = 15;

/// `previous_digest` of a genesis checkpoint: there is no parent to commit to.
pub const GENESIS_PREVIOUS_DIGEST: [u8; 32] = [0; 32];

/// Domain separator for signed checkpoint canonical bytes.
const CHECKPOINT_DOMAIN: &[u8] = b"cmtymeet.checkpoint.v1\0";
/// Domain separator for the fact canonical bytes (also the fact-ID preimage).
const FACT_DOMAIN: &[u8] = b"cmtymeet.fact.v1\0";

/// Seam failure: refused evaluation or rejected checkpoint/fact, never a lapse.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("empty community scope")]
    EmptyCommunity,
    #[error("checkpoint signature invalid")]
    BadCheckpointSignature,
    #[error("publishing ring proof invalid")]
    BadRingProof,
    #[error("publishing ring transition does not chain to the installed ring")]
    RingNotChained,
    #[error("checkpoint community mismatch")]
    CommunityMismatch,
    #[error("checkpoint sequence gap: expected {expected}, got {got}")]
    SequenceGap { expected: u64, got: u64 },
    #[error("checkpoint sequence moves backwards: last {last}, got {got}")]
    SequenceBackwards { last: u64, got: u64 },
    #[error("checkpoint replay: sequence {got} already applied")]
    SequenceReplay { got: u64 },
    #[error("checkpoint tick gap: expected {expected}, got {got}")]
    TickGap { expected: u64, got: u64 },
    #[error("checkpoint tick moves backwards: last {last}, got {got}")]
    TickBackwards { last: u64, got: u64 },
    #[error("checkpoint tick replay: tick {got} already applied")]
    TickReplay { got: u64 },
    #[error("checkpoint previous-digest mismatch")]
    PreviousDigestMismatch,
    #[error("genesis checkpoint must start at sequence 0")]
    GenesisSequence,
    #[error("genesis checkpoint must start at tick 0")]
    GenesisTick,
    #[error("genesis checkpoint must commit to the zero digest")]
    GenesisPreviousDigest,
    #[error("invalid author key")]
    InvalidAuthorKey,
    #[error("fact signature invalid")]
    BadFactSignature,
    #[error(
        "fact frontier beyond checkpoint: fact tick {fact_tick} > checkpoint tick {checkpoint_tick}"
    )]
    FrontierBeyondCheckpoint {
        fact_tick: u64,
        checkpoint_tick: u64,
    },
    #[error("tick arithmetic overflow")]
    TickOverflow,
}

/// Community seconds of a signed tick from the signed origin.
///
/// Pure tick arithmetic: no device clock is read. `None` on overflow.
pub fn tick_time(tick: u64) -> Result<u64, Error> {
    tick.checked_mul(TICK_SECONDS).ok_or(Error::TickOverflow)
}

/// Half-open validity predicate `[start_tick, end_tick)`.
///
/// Equality with `end_tick` means expired. A degenerate or inverted interval
/// is never live.
pub fn interval_live(start_tick: u64, end_tick: u64, at_tick: u64) -> bool {
    start_tick <= at_tick && at_tick < end_tick
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    push_u64(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn push_digest(out: &mut Vec<u8>, value: &[u8; 32]) {
    out.extend_from_slice(value);
}

/// Signed community checkpoint content, design §2:
/// `(community, sequence, previous_digest, tick, fact_roots, policy_root)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    community: String,
    sequence: u64,
    previous_digest: [u8; 32],
    tick: u64,
    fact_roots: Vec<[u8; 32]>,
    policy_root: [u8; 32],
}

impl Checkpoint {
    pub fn new(
        community: &str,
        sequence: u64,
        previous_digest: [u8; 32],
        tick: u64,
        fact_roots: Vec<[u8; 32]>,
        policy_root: [u8; 32],
    ) -> Result<Self, Error> {
        if community.is_empty() {
            return Err(Error::EmptyCommunity);
        }
        Ok(Self {
            community: community.into(),
            sequence,
            previous_digest,
            tick,
            fact_roots,
            policy_root,
        })
    }

    pub fn community(&self) -> &str {
        &self.community
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn previous_digest(&self) -> &[u8; 32] {
        &self.previous_digest
    }

    pub fn tick(&self) -> u64 {
        self.tick
    }

    pub fn fact_roots(&self) -> &[[u8; 32]] {
        &self.fact_roots
    }

    pub fn policy_root(&self) -> &[u8; 32] {
        &self.policy_root
    }

    /// Canonical bytes: the signed message and the chain-digest preimage.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CHECKPOINT_DOMAIN);
        push_str(&mut out, &self.community);
        push_u64(&mut out, self.sequence);
        push_digest(&mut out, &self.previous_digest);
        push_u64(&mut out, self.tick);
        push_u64(&mut out, self.fact_roots.len() as u64);
        for root in &self.fact_roots {
            push_digest(&mut out, root);
        }
        push_digest(&mut out, &self.policy_root);
        out
    }

    /// Digest of the canonical bytes, committed to by the next checkpoint.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.canonical_bytes()).into()
    }
}

/// A checkpoint with the publishing key's signature over its canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    checkpoint: Checkpoint,
    signature: [u8; 64],
}

impl SignedCheckpoint {
    /// Sign with the community's current publishing key: the cvld service
    /// derives this Ed25519 key from the same seed as the `csgn` secret key
    /// it holds (`csgn::SecretKey` never exports, so the seam takes the key).
    pub fn sign(checkpoint: Checkpoint, publishing_key: &SigningKey) -> Self {
        let signature = publishing_key
            .sign(&checkpoint.canonical_bytes())
            .to_bytes();
        Self {
            checkpoint,
            signature,
        }
    }

    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// Signature check against the resolved publishing ring: accepts a
    /// checkpoint signed by any key the ring authorizes, and reports which
    /// one. Chain continuity is [`verify_chain`]; ring resolution is
    /// [`resolve_ring`].
    pub fn verify_signature(&self, ring: &KeyRing) -> Result<[u8; 32], Error> {
        let bytes = self.checkpoint.canonical_bytes();
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        for entry in ring.keys() {
            let key = VerifyingKey::from_bytes(&entry.public_key())
                .map_err(|_| Error::BadCheckpointSignature)?;
            if key.verify_strict(&bytes, &signature).is_ok() {
                return Ok(entry.public_key());
            }
        }
        Err(Error::BadCheckpointSignature)
    }
}

/// A checkpoint whose signature and chain position are already established.
///
/// Carrying this (rather than a [`SignedCheckpoint`]) is what authorizes an
/// evaluator to treat the checkpoint as agreed community time. `signer` is
/// the publishing key that authorized it, resolved from the ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    checkpoint: Checkpoint,
    digest: [u8; 32],
    signer: [u8; 32],
}

impl VerifiedCheckpoint {
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn signer(&self) -> &[u8; 32] {
        &self.signer
    }
}

/// Verify signature, scope, ring authority and chain continuity.
///
/// `ring` is the publishing ring resolved by [`resolve_ring`] from the pinned
/// root: the candidate must be signed by a key that ring authorizes.
/// `None` admits a genesis checkpoint (sequence 0, tick 0, zero parent
/// digest). Otherwise the candidate must advance both sequence and tick by
/// exactly one: no skipped or backwards ticks, no gap, no replay, and
/// `previous_digest` must commit to the previous checkpoint's canonical
/// bytes. Pure: no clocks, no storage, no mutation.
pub fn verify_chain(
    previous: Option<&VerifiedCheckpoint>,
    candidate: &SignedCheckpoint,
    ring: &KeyRing,
) -> Result<VerifiedCheckpoint, Error> {
    let signer = candidate.verify_signature(ring)?;
    let content = candidate.checkpoint();
    if content.community().is_empty() {
        return Err(Error::EmptyCommunity);
    }
    let Some(previous) = previous else {
        if content.sequence() != 0 {
            return Err(Error::GenesisSequence);
        }
        if content.tick() != 0 {
            return Err(Error::GenesisTick);
        }
        if content.previous_digest() != &GENESIS_PREVIOUS_DIGEST {
            return Err(Error::GenesisPreviousDigest);
        }
        return Ok(VerifiedCheckpoint {
            digest: content.digest(),
            checkpoint: content.clone(),
            signer,
        });
    };
    let last = previous.checkpoint();
    if content.community() != last.community() {
        return Err(Error::CommunityMismatch);
    }
    match content.sequence().cmp(&last.sequence()) {
        std::cmp::Ordering::Less => {
            return Err(Error::SequenceBackwards {
                last: last.sequence(),
                got: content.sequence(),
            });
        }
        std::cmp::Ordering::Equal => {
            return Err(Error::SequenceReplay {
                got: content.sequence(),
            });
        }
        std::cmp::Ordering::Greater => {
            let expected = last.sequence().saturating_add(1);
            if content.sequence() != expected {
                return Err(Error::SequenceGap {
                    expected,
                    got: content.sequence(),
                });
            }
        }
    }
    match content.tick().cmp(&last.tick()) {
        std::cmp::Ordering::Less => {
            return Err(Error::TickBackwards {
                last: last.tick(),
                got: content.tick(),
            });
        }
        std::cmp::Ordering::Equal => {
            return Err(Error::TickReplay {
                got: content.tick(),
            });
        }
        std::cmp::Ordering::Greater => {
            let expected = last.tick().saturating_add(1);
            if content.tick() != expected {
                return Err(Error::TickGap {
                    expected,
                    got: content.tick(),
                });
            }
        }
    }
    if content.previous_digest() != previous.digest() {
        return Err(Error::PreviousDigestMismatch);
    }
    Ok(VerifiedCheckpoint {
        digest: content.digest(),
        checkpoint: content.clone(),
        signer,
    })
}

/// Resolve the current publishing ring from the pinned root.
///
/// Walks `transitions` in order starting at `pinned_root` (the publishing
/// root key from deployment configuration, never from a feed response): each
/// proof must verify against the currently installed ring at its own issue
/// time, and must endorse exactly that ring as its predecessor. Revisions
/// never go down: a proof for any other predecessor is refused. Pure: the
/// issue-time walk needs no clock.
pub fn resolve_ring(pinned_root: &KeyRing, transitions: &[Vec<u8>]) -> Result<KeyRing, Error> {
    let mut current = pinned_root.clone();
    for proof in transitions {
        let transition =
            csgn::verify_transition_at_issue(&current, proof).map_err(|_| Error::BadRingProof)?;
        if transition.previous() != &current {
            return Err(Error::RingNotChained);
        }
        current = transition.next().clone();
    }
    Ok(current)
}

/// Canonical fact envelope, design §3: `(type, version, community, scope,
/// author, author_lineage, parent/frontier, checkpoint, policy_digest,
/// payload_commitment, signature)`.
///
/// The payload itself stays private; only its commitment enters the envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactEnvelope {
    fact_type: String,
    version: u32,
    community: String,
    scope: String,
    author: [u8; 32],
    author_lineage: u64,
    frontier: [u8; 32],
    checkpoint: u64,
    policy_digest: [u8; 32],
    payload_commitment: [u8; 32],
}

impl FactEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fact_type: &str,
        version: u32,
        community: &str,
        scope: &str,
        author: [u8; 32],
        author_lineage: u64,
        frontier: [u8; 32],
        checkpoint: u64,
        policy_digest: [u8; 32],
        payload_commitment: [u8; 32],
    ) -> Result<Self, Error> {
        if fact_type.is_empty() || community.is_empty() {
            return Err(Error::EmptyCommunity);
        }
        Ok(Self {
            fact_type: fact_type.into(),
            version,
            community: community.into(),
            scope: scope.into(),
            author,
            author_lineage,
            frontier,
            checkpoint,
            policy_digest,
            payload_commitment,
        })
    }

    pub fn fact_type(&self) -> &str {
        &self.fact_type
    }

    pub fn community(&self) -> &str {
        &self.community
    }

    pub fn author(&self) -> &[u8; 32] {
        &self.author
    }

    /// Agreed checkpoint tick this fact builds on.
    pub fn checkpoint(&self) -> u64 {
        self.checkpoint
    }

    /// Canonical bytes: the signed message and the fact-ID preimage.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(FACT_DOMAIN);
        push_str(&mut out, &self.fact_type);
        out.extend_from_slice(&self.version.to_be_bytes());
        push_str(&mut out, &self.community);
        push_str(&mut out, &self.scope);
        push_digest(&mut out, &self.author);
        push_u64(&mut out, self.author_lineage);
        push_digest(&mut out, &self.frontier);
        push_u64(&mut out, self.checkpoint);
        push_digest(&mut out, &self.policy_digest);
        push_digest(&mut out, &self.payload_commitment);
        out
    }

    /// Domain-separated digest of the canonical bytes. Same bytes give the
    /// same ID; the signature is not an input, so re-signed copies of one
    /// fact keep one ID and one effect.
    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(&self.canonical_bytes()).into()
    }
}

/// A fact envelope with the author's signature over its canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedFact {
    envelope: FactEnvelope,
    signature: [u8; 64],
}

impl SignedFact {
    pub fn sign(envelope: FactEnvelope, author: &SigningKey) -> Self {
        let signature = author.sign(&envelope.canonical_bytes()).to_bytes();
        Self {
            envelope,
            signature,
        }
    }

    pub fn envelope(&self) -> &FactEnvelope {
        &self.envelope
    }

    /// Establish authorship: the envelope is a fact only if the signature,
    /// the authority and the spend agree. Invalid signatures, stale authority
    /// and conflicting spends are not facts.
    pub fn verify(&self) -> Result<VerifiedFact, Error> {
        let author =
            VerifyingKey::from_bytes(&self.envelope.author).map_err(|_| Error::InvalidAuthorKey)?;
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        author
            .verify_strict(&self.envelope.canonical_bytes(), &signature)
            .map_err(|_| Error::BadFactSignature)?;
        Ok(VerifiedFact {
            id: self.envelope.id(),
            envelope: self.envelope.clone(),
        })
    }
}

/// A fact whose authorship is established. Equal IDs have one effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFact {
    envelope: FactEnvelope,
    id: [u8; 32],
}

impl VerifiedFact {
    pub fn envelope(&self) -> &FactEnvelope {
        &self.envelope
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }
}

/// Signed policy revision the evaluation runs under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub version: u64,
    pub digest: [u8; 32],
}

/// Frontier agreement check shared by every evaluator: each fact must belong
/// to the checkpoint's community and must not build on a tick past the
/// checkpoint. A missing current frontier refuses the operation instead of
/// excluding anyone.
pub fn check_frontier(
    facts_at_frontier: &[VerifiedFact],
    checkpoint: &VerifiedCheckpoint,
) -> Result<(), Error> {
    for fact in facts_at_frontier {
        if fact.envelope().community() != checkpoint.checkpoint().community() {
            return Err(Error::CommunityMismatch);
        }
        if fact.envelope().checkpoint() > checkpoint.checkpoint().tick() {
            return Err(Error::FrontierBeyondCheckpoint {
                fact_tick: fact.envelope().checkpoint(),
                checkpoint_tick: checkpoint.checkpoint().tick(),
            });
        }
    }
    Ok(())
}

/// Pure state evaluator: `State = f(facts_at_frontier, checkpoint,
/// policy_version)`.
///
/// Implementations must be total, deterministic functions of their inputs:
/// no timers, no background work, no stored-state mutation, no device clocks.
/// Same inputs give the same answer; different frontiers are explicitly
/// different observations.
pub trait StateEvaluator {
    type State;

    fn evaluate(
        &self,
        facts_at_frontier: &[VerifiedFact],
        checkpoint: &VerifiedCheckpoint,
        policy: &PolicyVersion,
    ) -> Result<Self::State, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed caller-supplied times for the `csgn` fixtures: constants, never a
    /// device clock.
    const PUBLISHER_NOW: u64 = 1_000;
    const PUBLISHER_MAX_VALIDITY: u64 = 86_400;

    /// The community publishing key held by the cvld service: a `csgn` signer
    /// plus the Ed25519 key derived from the same seed for checkpoint signing
    /// (`csgn::SecretKey` never exports, so the seam takes the key).
    struct Publisher {
        signer: csgn::Signer,
        key: SigningKey,
    }

    impl Publisher {
        fn new(seed: u8) -> Self {
            let mut seed_bytes = [seed; 32];
            let secret = csgn::SecretKey::from_seed(&mut seed_bytes);
            let key = SigningKey::from_bytes(&[seed; 32]);
            assert_eq!(secret.public_key(), key.verifying_key().to_bytes());
            let signer =
                csgn::Signer::new("toyalpha01", secret, PUBLISHER_NOW, PUBLISHER_MAX_VALIDITY)
                    .expect("publisher signer");
            Self { signer, key }
        }

        fn ring(&self) -> csgn::KeyRing {
            self.signer.key_ring().clone()
        }
    }

    fn author_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn genesis_candidate(publisher: &Publisher) -> SignedCheckpoint {
        let checkpoint =
            Checkpoint::new("toyalpha01", 0, GENESIS_PREVIOUS_DIGEST, 0, vec![], [7; 32])
                .expect("valid genesis content");
        SignedCheckpoint::sign(checkpoint, &publisher.key)
    }

    fn next_candidate(
        publisher: &Publisher,
        previous: &VerifiedCheckpoint,
        sequence: u64,
        tick: u64,
    ) -> SignedCheckpoint {
        let checkpoint = Checkpoint::new(
            "toyalpha01",
            sequence,
            *previous.digest(),
            tick,
            vec![[1; 32]],
            [7; 32],
        )
        .expect("valid checkpoint content");
        SignedCheckpoint::sign(checkpoint, &publisher.key)
    }

    fn fact_at(author: &SigningKey, commitment_byte: u8, tick: u64) -> VerifiedFact {
        let envelope = FactEnvelope::new(
            "visit",
            1,
            "toyalpha01",
            "group-lineage",
            author.verifying_key().to_bytes(),
            3,
            [2; 32],
            tick,
            [4; 32],
            [commitment_byte; 32],
        )
        .expect("valid fact content");
        SignedFact::sign(envelope, author)
            .verify()
            .expect("signed fact")
    }

    /// Minimal evaluator for the seam tests: counts facts and folds the first
    /// payload-commitment byte, so two frontiers show explicitly different
    /// states.
    struct CountingEvaluator;

    impl StateEvaluator for CountingEvaluator {
        type State = (usize, u64);

        fn evaluate(
            &self,
            facts_at_frontier: &[VerifiedFact],
            checkpoint: &VerifiedCheckpoint,
            _policy: &PolicyVersion,
        ) -> Result<Self::State, Error> {
            check_frontier(facts_at_frontier, checkpoint)?;
            let sum = facts_at_frontier
                .iter()
                .map(|fact| u64::from(fact.envelope().payload_commitment[0]))
                .sum();
            Ok((facts_at_frontier.len(), sum))
        }
    }

    fn policy() -> PolicyVersion {
        PolicyVersion {
            version: 1,
            digest: [7; 32],
        }
    }

    fn setup() -> (Publisher, csgn::KeyRing) {
        let publisher = Publisher::new(9);
        let ring = publisher.ring();
        (publisher, ring)
    }

    #[test]
    fn genesis_verifies_and_chain_advances_one_tick() {
        let (publisher, ring) = setup();
        let genesis = verify_chain(None, &genesis_candidate(&publisher), &ring).expect("genesis");
        assert_eq!(genesis.checkpoint().sequence(), 0);
        assert_eq!(genesis.checkpoint().tick(), 0);
        let next = next_candidate(&publisher, &genesis, 1, 1);
        let verified = verify_chain(Some(&genesis), &next, &ring).expect("child");
        assert_eq!(verified.checkpoint().sequence(), 1);
        assert_eq!(verified.checkpoint().tick(), 1);
        assert_eq!(verified.digest(), &verified.checkpoint().digest());
    }

    #[test]
    fn chain_rejects_sequence_gap() {
        let (publisher, ring) = setup();
        let genesis = verify_chain(None, &genesis_candidate(&publisher), &ring).expect("genesis");
        let gap = next_candidate(&publisher, &genesis, 2, 1);
        assert_eq!(
            verify_chain(Some(&genesis), &gap, &ring),
            Err(Error::SequenceGap {
                expected: 1,
                got: 2
            })
        );
    }

    #[test]
    fn chain_rejects_tick_gap() {
        let (publisher, ring) = setup();
        let genesis = verify_chain(None, &genesis_candidate(&publisher), &ring).expect("genesis");
        let gap = next_candidate(&publisher, &genesis, 1, 2);
        assert_eq!(
            verify_chain(Some(&genesis), &gap, &ring),
            Err(Error::TickGap {
                expected: 1,
                got: 2
            })
        );
    }

    #[test]
    fn chain_rejects_backwards_movement() {
        let (publisher, ring) = setup();
        let genesis = verify_chain(None, &genesis_candidate(&publisher), &ring).expect("genesis");
        let one = verify_chain(
            Some(&genesis),
            &next_candidate(&publisher, &genesis, 1, 1),
            &ring,
        )
        .expect("child");
        let backwards = next_candidate(&publisher, &one, 0, 0);
        assert_eq!(
            verify_chain(Some(&one), &backwards, &ring),
            Err(Error::SequenceBackwards { last: 1, got: 0 })
        );
        let tick_back = next_candidate(&publisher, &one, 2, 0);
        assert_eq!(
            verify_chain(Some(&one), &tick_back, &ring),
            Err(Error::TickBackwards { last: 1, got: 0 })
        );
    }

    #[test]
    fn chain_rejects_replay() {
        let (publisher, ring) = setup();
        let genesis = verify_chain(None, &genesis_candidate(&publisher), &ring).expect("genesis");
        let candidate = next_candidate(&publisher, &genesis, 1, 1);
        let one = verify_chain(Some(&genesis), &candidate, &ring).expect("child");
        assert_eq!(
            verify_chain(Some(&one), &candidate, &ring),
            Err(Error::SequenceReplay { got: 1 })
        );
        let same_tick = next_candidate(&publisher, &one, 2, 1);
        assert_eq!(
            verify_chain(Some(&one), &same_tick, &ring),
            Err(Error::TickReplay { got: 1 })
        );
    }

    #[test]
    fn checkpoint_signed_by_unknown_key_is_refused() {
        let (publisher, ring) = setup();
        let genesis = verify_chain(None, &genesis_candidate(&publisher), &ring).expect("genesis");
        let checkpoint = Checkpoint::new("toyalpha01", 1, *genesis.digest(), 1, vec![], [7; 32])
            .expect("valid content");
        let forged = SignedCheckpoint::sign(checkpoint, &author_key(77));
        assert_eq!(
            verify_chain(Some(&genesis), &forged, &ring),
            Err(Error::BadCheckpointSignature)
        );
    }

    #[test]
    fn checkpoint_signed_by_current_ring_key_is_accepted() {
        let (publisher, ring) = setup();
        let pinned = publisher.ring();
        let resolved = resolve_ring(&pinned, &[]).expect("empty walk keeps the pinned root");
        assert_eq!(resolved, pinned);
        assert_eq!(resolved, ring);
        let genesis =
            verify_chain(None, &genesis_candidate(&publisher), &resolved).expect("genesis");
        assert_eq!(genesis.signer(), &publisher.key.verifying_key().to_bytes());
    }

    #[test]
    fn publishing_rotation_advances_checkpoint_authority() {
        let (mut publisher, ring) = setup();
        let mut rotation_seed = [11; 32];
        let proof = publisher
            .signer
            .rotate_with_proof(
                csgn::SecretKey::from_seed(&mut rotation_seed),
                PUBLISHER_NOW,
                PUBLISHER_NOW + 1_000,
            )
            .expect("rotation proof");
        let rotated = resolve_ring(&ring, std::slice::from_ref(&proof)).expect("rotation resolves");
        assert_ne!(rotated, ring);
        let rotated_key = SigningKey::from_bytes(&[11; 32]);
        let checkpoint =
            Checkpoint::new("toyalpha01", 0, GENESIS_PREVIOUS_DIGEST, 0, vec![], [7; 32])
                .expect("valid content");
        let rotated_signed = SignedCheckpoint::sign(checkpoint, &rotated_key);
        assert_eq!(
            verify_chain(None, &rotated_signed, &ring),
            Err(Error::BadCheckpointSignature)
        );
        let accepted = verify_chain(None, &rotated_signed, &rotated).expect("rotated key accepted");
        assert_eq!(accepted.signer(), &rotated_key.verifying_key().to_bytes());
        let legacy = verify_chain(None, &genesis_candidate(&publisher), &rotated)
            .expect("retired key still listed");
        assert_eq!(legacy.signer(), &publisher.key.verifying_key().to_bytes());
    }

    #[test]
    fn ring_not_chained_to_pinned_root_is_refused() {
        let (mut publisher, ring) = setup();
        let mut stranger = Publisher::new(77);
        let mut stranger_seed = [78; 32];
        let stranger_proof = stranger
            .signer
            .rotate_with_proof(
                csgn::SecretKey::from_seed(&mut stranger_seed),
                PUBLISHER_NOW,
                PUBLISHER_NOW + 1_000,
            )
            .expect("stranger rotation proof");
        assert_eq!(
            resolve_ring(&ring, std::slice::from_ref(&stranger_proof)),
            Err(Error::BadRingProof)
        );
        let mut rotation_seed = [11; 32];
        let proof = publisher
            .signer
            .rotate_with_proof(
                csgn::SecretKey::from_seed(&mut rotation_seed),
                PUBLISHER_NOW,
                PUBLISHER_NOW + 1_000,
            )
            .expect("rotation proof");
        let advanced =
            resolve_ring(&ring, std::slice::from_ref(&proof)).expect("rotation resolves");
        assert_eq!(
            resolve_ring(&advanced, std::slice::from_ref(&proof)),
            Err(Error::RingNotChained)
        );
    }

    #[test]
    fn chain_rejects_wrong_previous_digest() {
        let (publisher, ring) = setup();
        let genesis = verify_chain(None, &genesis_candidate(&publisher), &ring).expect("genesis");
        let checkpoint =
            Checkpoint::new("toyalpha01", 1, [55; 32], 1, vec![], [7; 32]).expect("valid content");
        let tampered = SignedCheckpoint::sign(checkpoint, &publisher.key);
        assert_eq!(
            verify_chain(Some(&genesis), &tampered, &ring),
            Err(Error::PreviousDigestMismatch)
        );
    }

    #[test]
    fn genesis_rejects_nonzero_start() {
        let (publisher, ring) = setup();
        let seq = Checkpoint::new("toyalpha01", 1, GENESIS_PREVIOUS_DIGEST, 0, vec![], [7; 32])
            .expect("valid content");
        assert_eq!(
            verify_chain(None, &SignedCheckpoint::sign(seq, &publisher.key), &ring),
            Err(Error::GenesisSequence)
        );
        let tick = Checkpoint::new("toyalpha01", 0, GENESIS_PREVIOUS_DIGEST, 3, vec![], [7; 32])
            .expect("valid content");
        assert_eq!(
            verify_chain(None, &SignedCheckpoint::sign(tick, &publisher.key), &ring),
            Err(Error::GenesisTick)
        );
        let parent =
            Checkpoint::new("toyalpha01", 0, [1; 32], 0, vec![], [7; 32]).expect("valid content");
        assert_eq!(
            verify_chain(None, &SignedCheckpoint::sign(parent, &publisher.key), &ring),
            Err(Error::GenesisPreviousDigest)
        );
    }

    #[test]
    fn interval_boundary_semantics() {
        assert!(!interval_live(10, 20, 9));
        assert!(interval_live(10, 20, 10));
        assert!(interval_live(10, 20, 19));
        assert!(!interval_live(10, 20, 20));
        assert!(!interval_live(10, 20, 21));
        assert!(!interval_live(10, 10, 10));
        assert!(!interval_live(20, 10, 15));
    }

    #[test]
    fn fact_ids_are_deterministic() {
        let author = author_key(5);
        let first = fact_at(&author, 11, 1);
        let same = fact_at(&author, 11, 1);
        assert_eq!(first.id(), same.id());
        let other_payload = fact_at(&author, 12, 1);
        assert_ne!(first.id(), other_payload.id());
        let other_author = fact_at(&author_key(6), 11, 1);
        assert_ne!(first.id(), other_author.id());
    }

    #[test]
    fn fact_signature_is_checked() {
        let author = author_key(5);
        let envelope = FactEnvelope::new(
            "visit",
            1,
            "toyalpha01",
            "group-lineage",
            author.verifying_key().to_bytes(),
            3,
            [2; 32],
            1,
            [4; 32],
            [11; 32],
        )
        .expect("valid fact content");
        let mut tampered = envelope.clone();
        tampered.payload_commitment = [12; 32];
        let signed = SignedFact::sign(envelope, &author);
        assert!(signed.verify().is_ok());
        let replayed = SignedFact {
            envelope: tampered,
            signature: signed.signature,
        };
        assert_eq!(replayed.verify(), Err(Error::BadFactSignature));
    }

    #[test]
    fn evaluator_gives_different_results_for_different_frontiers() {
        let (publisher, ring) = setup();
        let genesis = verify_chain(None, &genesis_candidate(&publisher), &ring).expect("genesis");
        let checkpoint = verify_chain(
            Some(&genesis),
            &next_candidate(&publisher, &genesis, 1, 1),
            &ring,
        )
        .expect("child");
        let author = author_key(5);
        let frontier_a = vec![fact_at(&author, 11, 1)];
        let frontier_b = vec![fact_at(&author, 11, 1), fact_at(&author, 12, 1)];
        let state_a = CountingEvaluator
            .evaluate(&frontier_a, &checkpoint, &policy())
            .expect("frontier A evaluates");
        let state_b = CountingEvaluator
            .evaluate(&frontier_b, &checkpoint, &policy())
            .expect("frontier B evaluates");
        assert_eq!(state_a, (1, 11));
        assert_eq!(state_b, (2, 23));
        assert_ne!(state_a, state_b);
        let repeat = CountingEvaluator
            .evaluate(&frontier_a, &checkpoint, &policy())
            .expect("same inputs evaluate again");
        assert_eq!(state_a, repeat);
    }

    #[test]
    fn evaluator_refuses_facts_beyond_the_checkpoint() {
        let (publisher, ring) = setup();
        let genesis = verify_chain(None, &genesis_candidate(&publisher), &ring).expect("genesis");
        let checkpoint = verify_chain(
            Some(&genesis),
            &next_candidate(&publisher, &genesis, 1, 1),
            &ring,
        )
        .expect("child");
        let future = vec![fact_at(&author_key(5), 11, 5)];
        assert_eq!(
            CountingEvaluator.evaluate(&future, &checkpoint, &policy()),
            Err(Error::FrontierBeyondCheckpoint {
                fact_tick: 5,
                checkpoint_tick: 1
            })
        );
    }

    #[test]
    fn tick_time_scales_and_overflows_cleanly() {
        assert_eq!(tick_time(0), Ok(0));
        assert_eq!(tick_time(2), Ok(30));
        assert_eq!(tick_time(u64::MAX), Err(Error::TickOverflow));
    }
}
