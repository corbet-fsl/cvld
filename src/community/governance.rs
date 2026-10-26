//! Admin decision threshold primitive (work package P2).
//!
//! One digest-bound proposal/approval rule for every admin decision class.
//! Pure and self-contained: no network, no storage, no consumer wiring. A
//! later package integrates this with the state seam (P1) and the admin
//! endpoints.
//!
//! Contract (STATUS.md 2026-10-26, "one threshold primitive for every admin
//! decision"):
//!
//! - A proposal is a fact over a digest of
//!   `(community, class, setting, new_value, base_revision)`.
//! - An approval is a current admin's signature over the same digest.
//! - The change is IN FORCE when the valid approvals from CURRENT admins
//!   reach `threshold(class, n)`, or when a root signed it (root override).
//! - Rules per decision class (community settings): Alone = 1,
//!   Majority = floor(n/2) + 1, Quorum(p) = ceil(p * n) with 0 < p <= 1,
//!   Unanimous = n. With n = 1 every rule yields 1.
//! - Classes: Gates, AdminPool, AdminSet, Governance, Default. A class
//!   without its own rule uses Default.
//! - No deadlines: a proposal that has not reached its threshold stays
//!   pending, never lapses.
//! - Among competing proposals for the same setting, the first to reach its
//!   threshold (by agreed sequence) is in force; the others are void.
//! - Changing a rule is class Governance, evaluated under the rule in force
//!   (the caller passes the current rules in; new rules never apply to the
//!   change that adopts them).
//! - AdminSet: a promotion needs no approval from the promoted person; a
//!   demotion excludes the target from n and from the approvals; stepping
//!   down is always possible alone; the last admin can only step down or be
//!   removed by a root.
//! - Approvals from admins who are no longer current do not count.
//!
//! Cryptography is reused, not invented: `ed25519_dalek` signatures are
//! verified with `verify_strict` (as in `super::state`) and digests use
//! `sha2::Sha256`. No new key types, no new primitives.

use ed25519_dalek::{Signer as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

/// Domain separator for the proposal-digest canonical bytes.
const GOVERNANCE_DOMAIN: &[u8] = b"cmtymeet.governance.v1\0";

/// Decision classes. A class without its own rule in [`RuleSet`] uses
/// [`DecisionClass::Default`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DecisionClass {
    Gates,
    AdminPool,
    AdminSet,
    Governance,
    Default,
}

impl DecisionClass {
    /// Every class, for table-driven tests.
    pub const ALL: [DecisionClass; 5] = [
        DecisionClass::Gates,
        DecisionClass::AdminPool,
        DecisionClass::AdminSet,
        DecisionClass::Governance,
        DecisionClass::Default,
    ];

    fn tag(self) -> u8 {
        match self {
            DecisionClass::Gates => 1,
            DecisionClass::AdminPool => 2,
            DecisionClass::AdminSet => 3,
            DecisionClass::Governance => 4,
            DecisionClass::Default => 5,
        }
    }
}

/// Threshold rule for one decision class (a community setting).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdRule {
    /// Exactly one approval.
    Alone,
    /// floor(n/2) + 1 approvals.
    Majority,
    /// ceil(parts * n / of) approvals, with 0 < parts <= of.
    Quorum { parts: u32, of: u32 },
    /// All n current admins.
    Unanimous,
}

impl ThresholdRule {
    /// Checked quorum constructor: rejects `of == 0`, `parts == 0` and
    /// `parts > of`.
    pub fn quorum(parts: u32, of: u32) -> Result<Self, Error> {
        if of == 0 || parts == 0 || parts > of {
            return Err(Error::BadQuorum);
        }
        Ok(Self::Quorum { parts, of })
    }

    /// Number of valid approvals from current admins that puts a proposal in
    /// force. Pure integer math; quorum rounds up. With n == 1 every rule
    /// yields 1.
    pub fn threshold(&self, n: u64) -> Result<u64, Error> {
        match *self {
            ThresholdRule::Alone => Ok(1),
            ThresholdRule::Majority => Ok(n / 2 + 1),
            ThresholdRule::Quorum { parts, of } => {
                if of == 0 || parts == 0 || parts > of {
                    return Err(Error::BadQuorum);
                }
                let ceil = (parts as u128 * n as u128 + of as u128 - 1) / of as u128;
                Ok(ceil as u64)
            }
            ThresholdRule::Unanimous => Ok(n),
        }
    }
}

/// Rules in force: one threshold per class with [`DecisionClass::Default`]
/// as the fallback for classes without their own rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSet {
    default_rule: ThresholdRule,
    overrides: std::collections::BTreeMap<DecisionClass, ThresholdRule>,
}

impl RuleSet {
    /// Rules with `default_rule` for every class.
    pub fn new(default_rule: ThresholdRule) -> Self {
        Self {
            default_rule,
            overrides: std::collections::BTreeMap::new(),
        }
    }

    /// Set the rule for one class (builder).
    pub fn with_rule(mut self, class: DecisionClass, rule: ThresholdRule) -> Self {
        self.overrides.insert(class, rule);
        self
    }

    /// Rule in force for `class`, falling back to Default.
    pub fn rule_for(&self, class: DecisionClass) -> ThresholdRule {
        self.overrides
            .get(&class)
            .copied()
            .unwrap_or(self.default_rule)
    }
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    push_u64(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_u64(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// A proposal: the fact content behind one admin decision. The digest binds
/// exactly `(community, class, setting, new_value, base_revision)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    community: String,
    class: DecisionClass,
    setting: String,
    new_value: Vec<u8>,
    base_revision: u64,
}

impl Proposal {
    pub fn new(
        community: &str,
        class: DecisionClass,
        setting: &str,
        new_value: Vec<u8>,
        base_revision: u64,
    ) -> Result<Self, Error> {
        if community.is_empty() {
            return Err(Error::EmptyCommunity);
        }
        if setting.is_empty() {
            return Err(Error::EmptySetting);
        }
        Ok(Self {
            community: community.into(),
            class,
            setting: setting.into(),
            new_value,
            base_revision,
        })
    }

    pub fn class(&self) -> DecisionClass {
        self.class
    }

    pub fn setting(&self) -> &str {
        &self.setting
    }

    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(GOVERNANCE_DOMAIN);
        push_str(&mut out, &self.community);
        out.push(self.class.tag());
        push_str(&mut out, &self.setting);
        push_bytes(&mut out, &self.new_value);
        push_u64(&mut out, self.base_revision);
        out
    }

    /// Domain-separated digest of the canonical bytes. Approvals sign exactly
    /// these bytes; equal inputs give equal digests.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

/// An approval: one signature over a proposal digest.
///
/// No serde impls: `[u8; 64]` has none and this primitive owns no storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Approval {
    pub signer: [u8; 32],
    pub signature: [u8; 64],
}

impl Approval {
    /// Sign `digest` as `signer`.
    pub fn sign(signer: &ed25519_dalek::SigningKey, digest: &[u8; 32]) -> Self {
        Self {
            signer: signer.verifying_key().to_bytes(),
            signature: signer.sign(digest).to_bytes(),
        }
    }

    /// Verify strictly against `digest`. A bad key or a bad signature is not
    /// an error here: the approval simply does not count.
    fn valid_for(&self, digest: &[u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.signer) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        key.verify_strict(digest, &signature).is_ok()
    }
}

/// AdminSet change encoding: for class [`DecisionClass::AdminSet`] the
/// proposal's `new_value` must be exactly one op byte plus the 32-byte member
/// key, so the affected member is bound by the approved digest. No other
/// encoding is accepted.
const ADMIN_ADD_TAG: u8 = 1;
const ADMIN_REMOVE_TAG: u8 = 2;
const ADMIN_RESIGN_TAG: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdminChange {
    Add([u8; 32]),
    Remove([u8; 32]),
    Resign([u8; 32]),
}

/// Canonical `new_value` for an AdminSet promotion of `key`.
pub fn admin_add_value(key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.push(ADMIN_ADD_TAG);
    out.extend_from_slice(key);
    out
}

/// Canonical `new_value` for an AdminSet demotion of `key`.
pub fn admin_remove_value(key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.push(ADMIN_REMOVE_TAG);
    out.extend_from_slice(key);
    out
}

/// Canonical `new_value` for `key` stepping down.
pub fn admin_resign_value(key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.push(ADMIN_RESIGN_TAG);
    out.extend_from_slice(key);
    out
}

fn parse_admin_change(new_value: &[u8]) -> Result<AdminChange, Error> {
    if new_value.len() != 33 {
        return Err(Error::BadAdminChange);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&new_value[1..]);
    match new_value[0] {
        ADMIN_ADD_TAG => Ok(AdminChange::Add(key)),
        ADMIN_REMOVE_TAG => Ok(AdminChange::Remove(key)),
        ADMIN_RESIGN_TAG => Ok(AdminChange::Resign(key)),
        _ => Err(Error::BadAdminChange),
    }
}

/// Outcome of one proposal evaluation. `Void` never comes out of
/// [`evaluate`]; it is assigned by [`resolve_competing`] to the losers of a
/// decided setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    InForce,
    Pending { valid: u64, needed: u64 },
    Void,
}

/// Evaluate one proposal against a snapshot: the current admins, the current
/// root keys and the rules in force.
///
/// - A valid signature from a current root over the digest puts the proposal
///   in force on its own (root override).
/// - Otherwise valid signatures from current admins are counted (each admin
///   once; stale admins and bad signatures do not count) and compared with
///   `threshold(class, n)`. With zero effective admins nothing passes without
///   a root.
/// - AdminSet extras: a promotion ignores the promoted person's approval; a
///   demotion excludes the target from n and from the approvals; a
///   resignation is in force with the resigning member's own signature alone.
/// - No deadlines: anything short of the threshold is [`Outcome::Pending`].
pub fn evaluate(
    proposal: &Proposal,
    approvals: &[Approval],
    current_admins: &[[u8; 32]],
    roots: &[[u8; 32]],
    rules: &RuleSet,
) -> Result<Outcome, Error> {
    let digest = proposal.digest();
    let mut valid: BTreeSet<[u8; 32]> = BTreeSet::new();
    for approval in approvals {
        if approval.valid_for(&digest) {
            valid.insert(approval.signer);
        }
    }
    if valid.iter().any(|signer| roots.contains(signer)) {
        return Ok(Outcome::InForce);
    }
    let current: BTreeSet<[u8; 32]> = current_admins.iter().copied().collect();
    if proposal.class() == DecisionClass::AdminSet {
        return evaluate_admin_set(
            &parse_admin_change(&proposal.new_value)?,
            &valid,
            &current,
            rules,
        );
    }
    let rule = rules.rule_for(proposal.class());
    let counted = valid.intersection(&current).count() as u64;
    threshold_outcome(rule, current.len() as u64, counted)
}

/// AdminSet evaluation with the target/promotion/resignation edge rules.
fn evaluate_admin_set(
    change: &AdminChange,
    valid: &BTreeSet<[u8; 32]>,
    current: &BTreeSet<[u8; 32]>,
    rules: &RuleSet,
) -> Result<Outcome, Error> {
    let rule = rules.rule_for(DecisionClass::AdminSet);
    match *change {
        AdminChange::Add(key) => {
            // The promoted person need not (and cannot) approve: their
            // signature never counts, even if they already are an admin.
            let counted = valid
                .difference(&BTreeSet::from([key]))
                .filter(|signer| current.contains(*signer))
                .count() as u64;
            threshold_outcome(rule, current.len() as u64, counted)
        }
        AdminChange::Remove(key) => {
            // The demotion target is excluded from n and from the approvals.
            if !current.contains(&key) {
                return Err(Error::UnknownAdminTarget);
            }
            let effective: BTreeSet<[u8; 32]> = current
                .difference(&BTreeSet::from([key]))
                .copied()
                .collect();
            let counted = valid.intersection(&effective).count() as u64;
            threshold_outcome(rule, effective.len() as u64, counted)
        }
        AdminChange::Resign(key) => {
            // Stepping down is always possible alone: the member's own
            // signature suffices regardless of the rule in force.
            if !current.contains(&key) {
                return Err(Error::UnknownAdminTarget);
            }
            if valid.contains(&key) {
                Ok(Outcome::InForce)
            } else {
                Ok(Outcome::Pending {
                    valid: 0,
                    needed: 1,
                })
            }
        }
    }
}

/// Threshold comparison shared by the approval paths. With zero effective
/// admins nothing passes without a root (checked by the caller first).
/// `needed` is the rule's threshold for the effective n as computed; for
/// Unanimous/Quorum at n 0 that is 0, and the n == 0 guard still keeps the
/// outcome pending.
fn threshold_outcome(rule: ThresholdRule, n: u64, counted: u64) -> Result<Outcome, Error> {
    let needed = rule.threshold(n)?;
    if n == 0 {
        return Ok(Outcome::Pending { valid: 0, needed });
    }
    if counted >= needed {
        Ok(Outcome::InForce)
    } else {
        Ok(Outcome::Pending {
            valid: counted,
            needed,
        })
    }
}

/// Adjudicate competing proposals for the SAME setting, given in agreed
/// sequence order. The first proposal that reached its threshold wins and is
/// in force; every other is void. With no winner, pending proposals stay
/// pending (no deadlines).
pub fn resolve_competing(outcomes: &[Outcome]) -> Vec<Outcome> {
    let winner = outcomes
        .iter()
        .position(|outcome| *outcome == Outcome::InForce);
    match winner {
        None => outcomes.to_vec(),
        Some(first) => outcomes
            .iter()
            .enumerate()
            .map(|(index, _)| {
                if index == first {
                    Outcome::InForce
                } else {
                    Outcome::Void
                }
            })
            .collect(),
    }
}

/// Seam failure: refused proposal or rule content, never a lapse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("empty community scope")]
    EmptyCommunity,
    #[error("empty setting name")]
    EmptySetting,
    #[error("quorum needs 0 < parts <= of")]
    BadQuorum,
    #[error("admin change value must be one op byte plus a 32-byte key")]
    BadAdminChange,
    #[error("demotion or resignation target is not a current admin")]
    UnknownAdminTarget,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn public(byte: u8) -> [u8; 32] {
        key(byte).verifying_key().to_bytes()
    }

    fn proposal(class: DecisionClass, setting: &str) -> Proposal {
        Proposal::new("toyalpha01", class, setting, b"value".to_vec(), 7).expect("proposal")
    }

    fn approve(signer: &SigningKey, digest: &[u8; 32]) -> Approval {
        Approval::sign(signer, digest)
    }

    fn admins(bytes: &[u8]) -> Vec<[u8; 32]> {
        bytes.iter().map(|b| public(*b)).collect()
    }

    fn majority_rules() -> RuleSet {
        RuleSet::new(ThresholdRule::Majority)
    }

    #[test]
    fn threshold_table_n1_to_n4() {
        let cases: &[(ThresholdRule, [u64; 4])] = &[
            (ThresholdRule::Alone, [1, 1, 1, 1]),
            (ThresholdRule::Majority, [1, 2, 2, 3]),
            (ThresholdRule::Unanimous, [1, 2, 3, 4]),
            (ThresholdRule::quorum(1, 2).unwrap(), [1, 1, 2, 2]),
            (ThresholdRule::quorum(1, 3).unwrap(), [1, 1, 1, 2]),
            (ThresholdRule::quorum(2, 3).unwrap(), [1, 2, 2, 3]),
            (ThresholdRule::quorum(3, 4).unwrap(), [1, 2, 3, 3]),
            (ThresholdRule::quorum(1, 1).unwrap(), [1, 2, 3, 4]),
        ];
        for (rule, expected) in cases {
            for (i, want) in expected.iter().enumerate() {
                let n = i as u64 + 1;
                assert_eq!(rule.threshold(n).unwrap(), *want, "{rule:?} n={n}");
            }
        }
    }

    #[test]
    fn every_rule_yields_one_with_single_admin() {
        let rules = [
            ThresholdRule::Alone,
            ThresholdRule::Majority,
            ThresholdRule::Unanimous,
            ThresholdRule::quorum(1, 2).unwrap(),
            ThresholdRule::quorum(1, 1000).unwrap(),
            ThresholdRule::quorum(999, 1000).unwrap(),
            ThresholdRule::quorum(1, 1).unwrap(),
        ];
        for rule in rules {
            assert_eq!(rule.threshold(1).unwrap(), 1, "{rule:?}");
        }
    }

    #[test]
    fn bad_quorum_rejected() {
        assert_eq!(ThresholdRule::quorum(0, 2), Err(Error::BadQuorum));
        assert_eq!(ThresholdRule::quorum(3, 2), Err(Error::BadQuorum));
        assert_eq!(ThresholdRule::quorum(1, 0), Err(Error::BadQuorum));
        assert_eq!(
            ThresholdRule::Quorum { parts: 0, of: 2 }.threshold(3),
            Err(Error::BadQuorum)
        );
        assert_eq!(
            ThresholdRule::Quorum { parts: 2, of: 1 }.threshold(3),
            Err(Error::BadQuorum)
        );
    }

    #[test]
    fn digest_deterministic_and_sensitive() {
        let base = proposal(DecisionClass::Gates, "entry");
        assert_eq!(base.digest(), base.digest());
        let mut other_setting = proposal(DecisionClass::Gates, "exit");
        assert_ne!(base.digest(), other_setting.digest());
        other_setting = Proposal::new(
            "toyalpha01",
            DecisionClass::Gates,
            "entry",
            b"other".to_vec(),
            7,
        )
        .unwrap();
        assert_ne!(base.digest(), other_setting.digest());
        let other_class = proposal(DecisionClass::AdminPool, "entry");
        assert_ne!(base.digest(), other_class.digest());
        let other_revision = Proposal::new(
            "toyalpha01",
            DecisionClass::Gates,
            "entry",
            b"value".to_vec(),
            8,
        )
        .unwrap();
        assert_ne!(base.digest(), other_revision.digest());
        assert_eq!(
            Proposal::new("", DecisionClass::Gates, "s", vec![], 0),
            Err(Error::EmptyCommunity)
        );
        assert_eq!(
            Proposal::new("c", DecisionClass::Gates, "", vec![], 0),
            Err(Error::EmptySetting)
        );
    }

    #[test]
    fn root_override_wins_without_admin_approvals() {
        let root = key(99);
        let prop = proposal(DecisionClass::Gates, "entry");
        let digest = prop.digest();
        // Unanimous with 4 admins, zero admin approvals: root alone suffices.
        let current = admins(&[1, 2, 3, 4]);
        let rules = RuleSet::new(ThresholdRule::Unanimous);
        let approvals = [approve(&root, &digest)];
        assert_eq!(
            evaluate(&prop, &approvals, &current, &[public(99)], &rules),
            Ok(Outcome::InForce)
        );
        // A forged root signature (wrong key bytes over the digest) is ignored.
        let mut forged = approve(&key(100), &digest);
        forged.signer = public(99);
        assert_eq!(
            evaluate(&prop, &[forged], &current, &[public(99)], &rules),
            Ok(Outcome::Pending {
                valid: 0,
                needed: 4
            })
        );
    }

    #[test]
    fn majority_proposal_reaches_threshold() {
        let prop = proposal(DecisionClass::Gates, "entry");
        let digest = prop.digest();
        let current = admins(&[1, 2, 3]);
        let rules = majority_rules();
        let one = [approve(&key(1), &digest)];
        assert_eq!(
            evaluate(&prop, &one, &current, &[], &rules),
            Ok(Outcome::Pending {
                valid: 1,
                needed: 2
            })
        );
        let two = [approve(&key(1), &digest), approve(&key(2), &digest)];
        assert_eq!(
            evaluate(&prop, &two, &current, &[], &rules),
            Ok(Outcome::InForce)
        );
    }

    #[test]
    fn stale_admin_approval_ignored() {
        let prop = proposal(DecisionClass::Gates, "entry");
        let digest = prop.digest();
        // Key 9 signed validly but is no longer a current admin.
        let current = admins(&[1, 2]);
        let rules = majority_rules();
        let approvals = [approve(&key(1), &digest), approve(&key(9), &digest)];
        assert_eq!(
            evaluate(&prop, &approvals, &current, &[], &rules),
            Ok(Outcome::Pending {
                valid: 1,
                needed: 2
            })
        );
    }

    #[test]
    fn duplicate_and_invalid_approvals_count_once_or_not_at_all() {
        let prop = proposal(DecisionClass::Gates, "entry");
        let digest = prop.digest();
        let current = admins(&[1, 2]);
        let rules = RuleSet::new(ThresholdRule::Unanimous);
        let same_twice = [approve(&key(1), &digest), approve(&key(1), &digest)];
        assert_eq!(
            evaluate(&prop, &same_twice, &current, &[], &rules),
            Ok(Outcome::Pending {
                valid: 1,
                needed: 2
            })
        );
        // Valid signature, but over a different digest: does not count.
        let wrong_digest = proposal(DecisionClass::Gates, "other").digest();
        let wrong = [approve(&key(1), &digest), approve(&key(2), &wrong_digest)];
        assert_eq!(
            evaluate(&prop, &wrong, &current, &[], &rules),
            Ok(Outcome::Pending {
                valid: 1,
                needed: 2
            })
        );
    }

    #[test]
    fn class_without_own_rule_uses_default() {
        let prop = proposal(DecisionClass::Gates, "entry");
        let digest = prop.digest();
        let current = admins(&[1, 2, 3]);
        // Only AdminPool is overridden; Gates falls back to Default = Alone.
        let rules = RuleSet::new(ThresholdRule::Alone)
            .with_rule(DecisionClass::AdminPool, ThresholdRule::Unanimous);
        let one = [approve(&key(1), &digest)];
        assert_eq!(
            evaluate(&prop, &one, &current, &[], &rules),
            Ok(Outcome::InForce)
        );
        let pool = proposal(DecisionClass::AdminPool, "allowance");
        let pool_digest = pool.digest();
        let pool_one = [approve(&key(1), &pool_digest)];
        assert_eq!(
            evaluate(&pool, &pool_one, &current, &[], &rules),
            Ok(Outcome::Pending {
                valid: 1,
                needed: 3
            })
        );
    }

    #[test]
    fn promotion_ignores_promoted_person() {
        let newcomer = public(9);
        let prop = Proposal::new(
            "toyalpha01",
            DecisionClass::AdminSet,
            "members",
            admin_add_value(&newcomer),
            3,
        )
        .unwrap();
        let digest = prop.digest();
        let current = admins(&[1, 2]);
        let rules = majority_rules();
        // The promoted person signs too: their approval must not count.
        let approvals = [
            approve(&key(1), &digest),
            approve(&key(2), &digest),
            approve(&key(9), &digest),
        ];
        assert_eq!(
            evaluate(&prop, &approvals, &current, &[], &rules),
            Ok(Outcome::InForce)
        );
        // Only the promoted person approves: pending, nobody current signed.
        let only_newcomer = [approve(&key(9), &digest)];
        assert_eq!(
            evaluate(&prop, &only_newcomer, &current, &[], &rules),
            Ok(Outcome::Pending {
                valid: 0,
                needed: 2
            })
        );
    }

    #[test]
    fn demotion_excludes_target_from_n_and_approvals() {
        // Admins 1, 2, 3; demote 3. Majority over the remaining 2 needs 2.
        let target = public(3);
        let prop = Proposal::new(
            "toyalpha01",
            DecisionClass::AdminSet,
            "members",
            admin_remove_value(&target),
            3,
        )
        .unwrap();
        let digest = prop.digest();
        let current = admins(&[1, 2, 3]);
        let rules = majority_rules();
        let approvals = [
            approve(&key(1), &digest),
            approve(&key(2), &digest),
            approve(&key(3), &digest),
        ];
        // In force via 1+2 alone; 3's own approval is excluded, not needed.
        assert_eq!(
            evaluate(&prop, &approvals, &current, &[], &rules),
            Ok(Outcome::InForce)
        );
        // One remaining admin is not enough over an effective n of 2.
        let one = [approve(&key(1), &digest), approve(&key(3), &digest)];
        assert_eq!(
            evaluate(&prop, &one, &current, &[], &rules),
            Ok(Outcome::Pending {
                valid: 1,
                needed: 2
            })
        );
        // Demoting a stranger is refused, never evaluated.
        let stranger = Proposal::new(
            "toyalpha01",
            DecisionClass::AdminSet,
            "members",
            admin_remove_value(&public(77)),
            3,
        )
        .unwrap();
        assert_eq!(
            evaluate(&stranger, &approvals, &current, &[], &rules),
            Err(Error::UnknownAdminTarget)
        );
    }

    #[test]
    fn last_admin_steps_down_alone_but_cannot_be_demoted() {
        let current = admins(&[1]);
        let rules = RuleSet::new(ThresholdRule::Unanimous);
        // Demotion of the last admin: nobody left to approve, so pending...
        let demote = Proposal::new(
            "toyalpha01",
            DecisionClass::AdminSet,
            "members",
            admin_remove_value(&public(1)),
            3,
        )
        .unwrap();
        let demote_digest = demote.digest();
        let self_approval = [approve(&key(1), &demote_digest)];
        // Effective n is 0 (the target is excluded) and their own approval
        // does not count: pending with the rule's degenerate threshold of 0.
        // Only a root can remove the last admin (asserted below).
        assert_eq!(
            evaluate(&demote, &self_approval, &current, &[], &rules),
            Ok(Outcome::Pending {
                valid: 0,
                needed: 0
            })
        );
        // ...unless a root removes them.
        assert_eq!(
            evaluate(
                &demote,
                &[approve(&key(99), &demote_digest)],
                &current,
                &[public(99)],
                &rules
            ),
            Ok(Outcome::InForce)
        );
        // Stepping down works alone with the member's own signature.
        let resign = Proposal::new(
            "toyalpha01",
            DecisionClass::AdminSet,
            "members",
            admin_resign_value(&public(1)),
            3,
        )
        .unwrap();
        let resign_digest = resign.digest();
        assert_eq!(
            evaluate(
                &resign,
                &[approve(&key(1), &resign_digest)],
                &current,
                &[],
                &rules
            ),
            Ok(Outcome::InForce)
        );
        // A stranger cannot file a resignation for a member.
        let stranger_resign = Proposal::new(
            "toyalpha01",
            DecisionClass::AdminSet,
            "members",
            admin_resign_value(&public(77)),
            3,
        )
        .unwrap();
        assert_eq!(
            evaluate(
                &stranger_resign,
                &[approve(&key(1), &resign_digest)],
                &current,
                &[],
                &rules
            ),
            Err(Error::UnknownAdminTarget)
        );
    }

    #[test]
    fn step_down_always_allowed_alone() {
        // Unanimous over 3, but 1 stepping down needs only their own signature.
        let current = admins(&[1, 2, 3]);
        let rules = RuleSet::new(ThresholdRule::Unanimous);
        let resign = Proposal::new(
            "toyalpha01",
            DecisionClass::AdminSet,
            "members",
            admin_resign_value(&public(1)),
            3,
        )
        .unwrap();
        let digest = resign.digest();
        assert_eq!(
            evaluate(&resign, &[approve(&key(1), &digest)], &current, &[], &rules),
            Ok(Outcome::InForce)
        );
        // Without their own signature the resignation stays pending.
        let others = [approve(&key(2), &digest), approve(&key(3), &digest)];
        assert_eq!(
            evaluate(&resign, &others, &current, &[], &rules),
            Ok(Outcome::Pending {
                valid: 0,
                needed: 1
            })
        );
    }

    #[test]
    fn bad_admin_encoding_refused() {
        let current = admins(&[1, 2]);
        let rules = majority_rules();
        for raw in [vec![], vec![9u8; 33], vec![1u8; 32], vec![2u8; 34]] {
            let prop =
                Proposal::new("toyalpha01", DecisionClass::AdminSet, "members", raw, 3).unwrap();
            assert_eq!(
                evaluate(&prop, &[], &current, &[], &rules),
                Err(Error::BadAdminChange)
            );
        }
    }

    #[test]
    fn competing_first_past_the_post_wins_rest_void() {
        let in_force = Outcome::InForce;
        let pending = Outcome::Pending {
            valid: 1,
            needed: 2,
        };
        // Both reached: the first in agreed order wins, the other is void.
        assert_eq!(
            resolve_competing(&[in_force, in_force]),
            vec![Outcome::InForce, Outcome::Void]
        );
        // Winner first, pending second: the pending one is void, not pending.
        assert_eq!(
            resolve_competing(&[in_force, pending]),
            vec![Outcome::InForce, Outcome::Void]
        );
        // Pending first, winner second: the earlier one is void once beaten.
        assert_eq!(
            resolve_competing(&[pending, in_force]),
            vec![Outcome::Void, Outcome::InForce]
        );
        // No winner: pending proposals stay pending, nothing lapses.
        assert_eq!(
            resolve_competing(&[pending, pending]),
            vec![pending, pending]
        );
        assert_eq!(resolve_competing(&[]), vec![]);
    }

    #[test]
    fn governance_change_evaluated_under_rule_in_force() {
        // Governance rule in force is Unanimous over admins 1, 2.
        let rules = RuleSet::new(ThresholdRule::Majority)
            .with_rule(DecisionClass::Governance, ThresholdRule::Unanimous);
        let change = Proposal::new(
            "toyalpha01",
            DecisionClass::Governance,
            "rule",
            b"majority".to_vec(),
            3,
        )
        .unwrap();
        let digest = change.digest();
        let current = admins(&[1, 2]);
        // One approval is not enough under the unanimous rule in force.
        assert_eq!(
            evaluate(&change, &[approve(&key(1), &digest)], &current, &[], &rules),
            Ok(Outcome::Pending {
                valid: 1,
                needed: 2
            })
        );
        // Both approvals put it in force; the new rule did not leak in early.
        assert_eq!(
            evaluate(
                &change,
                &[approve(&key(1), &digest), approve(&key(2), &digest)],
                &current,
                &[],
                &rules
            ),
            Ok(Outcome::InForce)
        );
    }
}
