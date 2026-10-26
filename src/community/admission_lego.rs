//! Admission Lego core (work package P3a).
//!
//! Pure logic for community admission under the state model
//! (`DESIGN-state-model-2026-10-26.md` §4.1-§4.3) with the final 2026-10-26
//! `STATUS.md` decisions applied (they override the design):
//!
//! - §4.1: every proof maps to a property/strength manifest with unsigned
//!   fixed-point strengths `0..10_000` (never probabilities). Scores stack per
//!   property over independence components: the maximum per component is
//!   summed and capped at 10_000. Duplicated proofs contribute once. Missing
//!   independence metadata merges into one unknown component, never presumed
//!   independent. Components are evaluated per property; cross-property
//!   evidence never adds to the wrong property. Permanent scores use only
//!   permanent evidence; current scores also use valid temporal evidence.
//! - §4.2: community requirements are `all_of` / `any_of` / `at_least(k)`
//!   expressions over leaves `property >= minimum`. Branch-complete anchor
//!   validation rejects any satisfiable branch that entails no allowed anchor
//!   at the platform threshold (unguarded OR branches, vacuous `at_least(0)`
//!   / empty `all_of`). `legal` is mandatory and never an anchor, a scored
//!   leaf, or an additive property. Community minima may strengthen but never
//!   weaken platform anchor bounds. Unknown properties are not satisfied by
//!   default (they score 0). The alpha's numeric ratings are mechanism
//!   parameters (M); the qualitative mapping is decided (STATUS Q1, row 1596).
//! - §4.3: membership is `permanent` (no admission-clock deadline, not
//!   immunity from future gates or legal orders), `on_the_clock` (full member
//!   rights until the deadline), or `excluded`, with the next deadline
//!   computed as the earliest future boundary whose crossing changes
//!   admission. Trust-bar colours per property are green (met by permanent
//!   evidence), yellow (met only with temporal evidence, with its boundary),
//!   red (fails, expired, or blocked); AND aggregates to the worst required
//!   colour, OR to the best satisfied branch, preserving per-check results.
//!
//! Alpha strengths (STATUS Q1): a personal voucher establishes `vouched`
//! strong (10_000, permanent evidence) and satisfies the platform anchor, so
//! the member is permanent; an admin voucher establishes `vouched` weak
//! (2_500, temporal evidence), so the member is on the clock and needs a
//! personal invite within the clock. There are no guests: every admitted
//! person is a full member, some memberships are on the clock (STATUS rows
//! 1576-1577). No providers that cost money and no per-gate valuation
//! research are built here (STATUS row 1578).
//!
//! This module is deliberately pure: no network, no storage, no clock reads,
//! no consumer wiring. Validity (expiry, revocation, role-epoch currency) is
//! decided by the caller from signed facts and the community checkpoint; this
//! module only consumes the resulting flags. Time is `u64` community ticks
//! (`TICK = 15 s`, design §2); durations resolve to whole ticks, intervals
//! are half-open `[start, end)`, and equality with `end` means expired. Clock
//! defaults are the decided values (STATUS rows 1576-1577: admin admission
//! 365 days by default, community range 30 days to 1 year); there is no
//! event-code brick in alpha. Clocks, pool accounting, admin governance and
//! legal verification belong to later packages (P3 pool work, P2 governance,
//! P4 legal); this core only decides admission and trust colours from
//! evidence.
//!
//! Contract-card check: no retry, timeout, cleanup job, TTL, offline queue,
//! guest tier, or device-clock comparison. The "clock" here is arithmetic on
//! signed-checkpoint ticks, not a timer. No custody, key, cryptographic, or
//! server-acceptance change: no signing or verification happens here.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum strength: fixed-point scale `0..10_000` (precision, not an anchor
/// valuation).
pub const STRENGTH_MAX: Strength = 10_000;

/// Unsigned fixed-point strength on the `0..10_000` scale.
pub type Strength = u16;

/// Community time in signed-checkpoint ticks (`TICK = 15 s`, design §2).
pub type Tick = u64;

/// A policed property (STATUS row 1573: personhood, uniqueness, money, social
/// trust, time, effort, presence, affiliation, origin, ...). Namespaced and
/// extensible: future modules declare their own names. Only the alpha voucher
/// properties below are populated.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Property(pub String);

impl Property {
    /// A namespaced property name declared by a proof module.
    pub fn new(name: impl Into<String>) -> Self {
        Property(name.into())
    }
}

/// Common social-accountability property established by both voucher pools.
pub const PROPERTY_VOUCHED: &str = "vouched";
/// Pool-specific personal-voucher property (only personal proofs raise it).
pub const PROPERTY_VOUCHED_PERSONAL: &str = "vouched.personal";
/// Pool-specific admin-voucher property (only admin proofs raise it).
pub const PROPERTY_VOUCHED_ADMIN: &str = "vouched.admin";
/// Legality: mandatory boolean gate, never a scored property or an anchor.
pub const PROPERTY_LEGAL: &str = "legal";

/// Alpha proof kinds: the free bricks (STATUS row 1578). No other provider is
/// implemented by this design.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofKind {
    /// Personal-pool voucher: strong, permanent evidence.
    PersonalVoucher,
    /// Admin-pool voucher: weak, temporal evidence on the selected clock.
    AdminVoucher,
}

/// One manifest line: the property a proof establishes and how strongly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contribution {
    pub property: Property,
    pub strength: Strength,
}

/// The proof → property/strength manifest of one proof kind, plus whether its
/// evidence is permanent or temporal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub contributions: Vec<Contribution>,
    pub permanent: bool,
}

/// Alpha strength: personal voucher = vouched strong (STATUS Q1). A mechanism
/// parameter (M); the qualitative mapping is decided, the number is not
/// researched.
pub const PERSONAL_VOUCH_STRENGTH: Strength = 10_000;
/// Alpha strength: admin voucher = vouched weak (STATUS Q1). A mechanism
/// parameter (M), like [`PERSONAL_VOUCH_STRENGTH`].
pub const ADMIN_VOUCH_STRENGTH: Strength = 2_500;

/// The manifest for an alpha proof kind: which properties it establishes, how
/// strongly, and whether the evidence is permanent.
pub fn alpha_manifest(kind: ProofKind) -> Manifest {
    match kind {
        ProofKind::PersonalVoucher => Manifest {
            contributions: vec![
                Contribution {
                    property: Property::new(PROPERTY_VOUCHED),
                    strength: PERSONAL_VOUCH_STRENGTH,
                },
                Contribution {
                    property: Property::new(PROPERTY_VOUCHED_PERSONAL),
                    strength: PERSONAL_VOUCH_STRENGTH,
                },
            ],
            permanent: true,
        },
        ProofKind::AdminVoucher => Manifest {
            contributions: vec![
                Contribution {
                    property: Property::new(PROPERTY_VOUCHED),
                    strength: ADMIN_VOUCH_STRENGTH,
                },
                Contribution {
                    property: Property::new(PROPERTY_VOUCHED_ADMIN),
                    strength: ADMIN_VOUCH_STRENGTH,
                },
            ],
            permanent: false,
        },
    }
}

/// One presented proof with its validity as decided by the caller from signed
/// facts and the community checkpoint (unexpired, unrevoked, applicable,
/// role-epoch current). This module never re-derives validity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Proof identity: duplicated proofs (equal id) contribute once; the
    /// first occurrence wins.
    pub id: String,
    /// Alpha proof kind; selects the manifest.
    pub kind: ProofKind,
    /// Independence component key (e.g. sponsor/control-domain plus voucher
    /// unit). `None` means unknown: all such proofs merge into one component,
    /// never presumed independent.
    pub independence: Option<String>,
    /// Currently valid (unexpired, unrevoked, applicable).
    pub valid: bool,
    /// Half-open validity end `[.., valid_until)`: `None` is permanent (no
    /// time boundary). Equality with the evaluation tick means expired.
    pub valid_until: Option<Tick>,
}

/// Which evidence class a score is computed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceClass {
    /// Only permanent evidence (for permanent paths).
    Permanent,
    /// Permanent plus valid temporal evidence (for current admission).
    Current,
}

/// Stacked score of `property`: per independence component the maximum
/// contributed strength, summed over components and capped at
/// [`STRENGTH_MAX`]. Components are evaluated per property; evidence for one
/// property never adds to another. Invalid proofs contribute nothing, and
/// duplicated proof ids contribute once (first occurrence wins).
pub fn score(property: &Property, evidence: &[Evidence], class: EvidenceClass) -> Strength {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut components: BTreeMap<Option<&str>, Strength> = BTreeMap::new();
    for e in evidence {
        // Duplicated proofs contribute once; the first occurrence wins.
        if !seen.insert(e.id.as_str()) {
            continue;
        }
        if !e.valid {
            continue;
        }
        let manifest = alpha_manifest(e.kind);
        if matches!(class, EvidenceClass::Permanent) && !manifest.permanent {
            continue;
        }
        let best = manifest
            .contributions
            .iter()
            .filter(|c| &c.property == property)
            .map(|c| c.strength)
            .max()
            .unwrap_or(0);
        let slot = components.entry(e.independence.as_deref()).or_insert(0);
        *slot = (*slot).max(best);
    }
    components
        .values()
        .fold(0u32, |sum, s| sum + Strength::from(*s))
        .min(Strength::from(STRENGTH_MAX))
        .try_into()
        .unwrap_or(STRENGTH_MAX)
}

/// A community requirement expression: `all_of` / `any_of` / `at_least(k)`
/// over leaves `property >= minimum_strength`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Requirement {
    /// Leaf: the property's score must reach at least `minimum`.
    Property {
        property: Property,
        minimum: Strength,
    },
    /// Conjunction: every child must hold (vacuously true when empty).
    AllOf(Vec<Requirement>),
    /// Disjunction: at least one child must hold (false when empty).
    AnyOf(Vec<Requirement>),
    /// At least `k` of the children must hold.
    AtLeast {
        k: usize,
        children: Vec<Requirement>,
    },
}

/// Evaluate a requirement expression against a score function. Unknown
/// properties score 0 and are therefore not satisfied by default (unless the
/// leaf minimum is 0, which is vacuous).
pub fn satisfies(req: &Requirement, score: &dyn Fn(&Property) -> Strength) -> bool {
    match req {
        Requirement::Property { property, minimum } => score(property) >= *minimum,
        Requirement::AllOf(children) => children.iter().all(|c| satisfies(c, score)),
        Requirement::AnyOf(children) => children.iter().any(|c| satisfies(c, score)),
        Requirement::AtLeast { k, children } => {
            children.iter().filter(|c| satisfies(c, score)).count() >= *k
        }
    }
}

/// One allowed anchor: an anchor-listed property at the platform threshold.
/// Alpha: `(vouched, strong)` guards permanent paths; `(vouched, weak)`
/// floors temporal paths (see [`AdmissionPolicy`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorEntry {
    pub property: Property,
    pub minimum: Strength,
}

/// An anchor as a disjunction of allowed entries (`any_of`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub any_of: Vec<AnchorEntry>,
}

impl Anchor {
    /// Whether any anchor entry is met by the given scores.
    pub fn satisfied(&self, score: &dyn Fn(&Property) -> Strength) -> bool {
        self.any_of
            .iter()
            .any(|e| score(&e.property) >= e.minimum)
    }
}

/// The admission clock rule: a temporal admission lasts `duration_ticks` from
/// its start. Half-open: the member is on the clock for
/// `[start, start + duration)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockRule {
    /// Selected clock length in ticks (community choice within bounds).
    pub duration_ticks: Tick,
    /// Platform lower bound (STATUS: 30 days).
    pub min_ticks: Tick,
    /// Platform upper bound (STATUS: 1 year).
    pub max_ticks: Tick,
}

/// 30 days in 15 s ticks: the community-settable clock minimum.
pub const MIN_CLOCK_TICKS: Tick = 172_800;
/// 365 days in 15 s ticks: the default admin clock and the maximum.
pub const MAX_CLOCK_TICKS: Tick = 2_102_400;
/// Default admin admission clock: 365 days (STATUS row 1576).
pub const ALPHA_CLOCK_TICKS: Tick = 2_102_400;

/// Path id of the alpha temporal path (the admin voucher clock).
pub const ALPHA_TEMPORAL_PATH: &str = "admin-clock";

/// The community's assembled admission bricks: anchors, requirement
/// expressions per path class, the temporal path's exit rule, and the clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    /// Platform anchor for permanent paths: every satisfiable permanent
    /// branch must entail one entry. Alpha: `(vouched, strong)`.
    pub permanent_anchor: Anchor,
    /// Admission floor for temporal paths: every satisfiable temporal branch
    /// must entail one entry. Provisional paths carry a clock instead of the
    /// strong anchor. Alpha: `(vouched, weak)`.
    pub temporal_floor: Anchor,
    /// Expression a permanent admission must satisfy (over permanent scores).
    pub permanent_if: Requirement,
    /// Expression a temporal admission must satisfy (over current scores).
    /// `None` means the community admits permanent members only.
    pub temporal_if: Option<Requirement>,
    /// Path id of the temporal path (for the spent-path set).
    pub temporal_path: String,
    /// Whether an exhausted temporal path may be re-entered with fresh proof.
    /// Default false: exclusion with no re-entry is the earlier default
    /// (STATUS rows 1576-1577), not a universal Lego rule.
    pub allow_reentry: bool,
    /// The selected clock for temporal admissions.
    pub clock: ClockRule,
}

/// The alpha community policy: personal voucher → permanent, admin voucher →
/// on the admin clock, nothing else admitted.
pub fn alpha_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        permanent_anchor: Anchor {
            any_of: vec![AnchorEntry {
                property: Property::new(PROPERTY_VOUCHED),
                minimum: PERSONAL_VOUCH_STRENGTH,
            }],
        },
        temporal_floor: Anchor {
            any_of: vec![AnchorEntry {
                property: Property::new(PROPERTY_VOUCHED),
                minimum: ADMIN_VOUCH_STRENGTH,
            }],
        },
        permanent_if: Requirement::Property {
            property: Property::new(PROPERTY_VOUCHED),
            minimum: PERSONAL_VOUCH_STRENGTH,
        },
        temporal_if: Some(Requirement::Property {
            property: Property::new(PROPERTY_VOUCHED),
            minimum: ADMIN_VOUCH_STRENGTH,
        }),
        temporal_path: ALPHA_TEMPORAL_PATH.to_string(),
        allow_reentry: false,
        clock: ClockRule {
            duration_ticks: ALPHA_CLOCK_TICKS,
            min_ticks: MIN_CLOCK_TICKS,
            max_ticks: MAX_CLOCK_TICKS,
        },
    }
}

/// Platform anchor bounds a community policy is validated against. Community
/// minima may strengthen but never weaken these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformBounds {
    /// Minimum permanent-anchor entries: the policy must entail at least
    /// these minima per listed property.
    pub permanent_anchor_min: Vec<AnchorEntry>,
    /// Minimum temporal-floor entries, same rule.
    pub temporal_floor_min: Vec<AnchorEntry>,
}

/// Alpha platform bounds: the anchor minima the alpha policy meets exactly.
pub fn alpha_platform_bounds() -> PlatformBounds {
    PlatformBounds {
        permanent_anchor_min: vec![AnchorEntry {
            property: Property::new(PROPERTY_VOUCHED),
            minimum: PERSONAL_VOUCH_STRENGTH,
        }],
        temporal_floor_min: vec![AnchorEntry {
            property: Property::new(PROPERTY_VOUCHED),
            minimum: ADMIN_VOUCH_STRENGTH,
        }],
    }
}

/// Which path class an unguarded branch belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathSide {
    Permanent,
    Temporal,
}

/// Why a community policy was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// `legal` was listed as an anchor entry. Legality is mandatory and never
    /// an anchor substitute.
    LegalNeverAnchor,
    /// A requirement leaf names `legal`. Legality is a separate boolean gate,
    /// never a scored leaf.
    LegalNotScored,
    /// A satisfiable branch entails no allowed anchor (unguarded OR branch,
    /// vacuous `at_least(0)`, or empty `all_of`).
    UnguardedBranch {
        side: PathSide,
    },
    /// The expression can never be satisfied (empty `any_of`, or
    /// `at_least(k)` with `k` above the child count). Rejected loudly at
    /// policy time instead of silently excluding everyone.
    UnsatisfiableRequirement,
    /// A strength minimum above [`STRENGTH_MAX`]: unreachable by construction.
    StrengthOutOfRange,
    /// A community anchor minimum weakens the platform bound for the same
    /// property (a missing entry counts as weakened to 0).
    WeakenedAnchor {
        property: Property,
        platform_minimum: Strength,
        community_minimum: Strength,
    },
    /// No anchor entries at all: nothing could ever entail the anchor.
    EmptyAnchor,
    /// The clock duration is zero or outside its platform bounds.
    BadClock,
}

/// A community policy that passed branch-complete anchor validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPolicy {
    policy: AdmissionPolicy,
}

impl ValidatedPolicy {
    /// The validated community policy.
    pub fn policy(&self) -> &AdmissionPolicy {
        &self.policy
    }
}

/// One satisfiable branch: conjunctive `(property, minimum)` constraints with
/// at most one minimum per property (the strongest wins on merge).
type Branch = Vec<(Property, Strength)>;

/// Merge two conjunctive branches, keeping the stronger minimum per property.
fn merge_branches(a: &Branch, b: &Branch) -> Branch {
    let mut merged: BTreeMap<&Property, Strength> = BTreeMap::new();
    for (p, m) in a.iter().chain(b.iter()) {
        let slot = merged.entry(p).or_insert(0);
        *slot = (*slot).max(*m);
    }
    merged
        .into_iter()
        .map(|(p, m)| (p.clone(), m))
        .collect()
}

/// Conjunctive product of two branch sets (for `all_of` and `at_least`
/// subsets): every combination of one branch from each side, merged.
fn product_branches(left: Vec<Branch>, right: Vec<Branch>) -> Vec<Branch> {
    let mut out = Vec::with_capacity(left.len() * right.len());
    for a in &left {
        for b in &right {
            out.push(merge_branches(a, b));
        }
    }
    out
}

/// Index combinations: all `k`-subsets of `0..n`, in lexicographic order.
fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    fn go(start: usize, n: usize, k: usize, prefix: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if k == 0 {
            out.push(prefix.clone());
            return;
        }
        for i in start..n {
            prefix.push(i);
            go(i + 1, n, k - 1, prefix, out);
            prefix.pop();
        }
    }
    let mut out = Vec::new();
    go(0, n, k, &mut Vec::new(), &mut out);
    out
}

/// Enumerate every satisfiable branch of a requirement expression. An
/// `at_least(0)` or empty `all_of` yields one empty branch (satisfied by
/// everything, entailing nothing — rejected as unguarded by the caller).
/// Dead expressions (empty `any_of`, `k` above the child count) are rejected.
fn branches(req: &Requirement) -> Result<Vec<Branch>, PolicyError> {
    match req {
        Requirement::Property { property, minimum } => {
            Ok(vec![vec![(property.clone(), *minimum)]])
        }
        Requirement::AllOf(children) => {
            let mut out = vec![Vec::new()];
            for c in children {
                out = product_branches(out, branches(c)?);
            }
            Ok(out)
        }
        Requirement::AnyOf(children) => {
            if children.is_empty() {
                return Err(PolicyError::UnsatisfiableRequirement);
            }
            let mut out = Vec::new();
            for c in children {
                out.extend(branches(c)?);
            }
            Ok(out)
        }
        Requirement::AtLeast { k, children } => {
            if *k > children.len() {
                return Err(PolicyError::UnsatisfiableRequirement);
            }
            let mut out = Vec::new();
            for subset in combinations(children.len(), *k) {
                let mut product = vec![Vec::new()];
                for i in subset {
                    product = product_branches(product, branches(&children[i])?);
                }
                out.extend(product);
            }
            Ok(out)
        }
    }
}

/// Whether a branch entails an anchor: some leaf on an anchor-listed property
/// with a minimum at or above the anchor threshold.
fn branch_entails_anchor(branch: &Branch, anchor: &Anchor) -> bool {
    anchor.any_of.iter().any(|e| {
        branch
            .iter()
            .any(|(p, m)| p == &e.property && *m >= e.minimum)
    })
}

fn is_legal(p: &Property) -> bool {
    p.0 == PROPERTY_LEGAL
}

/// Check one anchor list: entries must be in range, non-empty, and never
/// name `legal`.
fn check_anchor_entries(anchor: &Anchor) -> Result<(), PolicyError> {
    if anchor.any_of.is_empty() {
        return Err(PolicyError::EmptyAnchor);
    }
    for e in &anchor.any_of {
        if is_legal(&e.property) {
            return Err(PolicyError::LegalNeverAnchor);
        }
        if e.minimum > STRENGTH_MAX {
            return Err(PolicyError::StrengthOutOfRange);
        }
    }
    Ok(())
}

/// Check one requirement expression's leaves: `legal` is never scored and
/// minima must be reachable on the fixed scale.
fn check_requirement_leaves(req: &Requirement) -> Result<(), PolicyError> {
    match req {
        Requirement::Property { property, minimum } => {
            if is_legal(property) {
                return Err(PolicyError::LegalNotScored);
            }
            if *minimum > STRENGTH_MAX {
                return Err(PolicyError::StrengthOutOfRange);
            }
            Ok(())
        }
        Requirement::AllOf(children) | Requirement::AnyOf(children) => {
            children.iter().try_for_each(check_requirement_leaves)
        }
        Requirement::AtLeast { children, .. } => {
            children.iter().try_for_each(check_requirement_leaves)
        }
    }
}

/// Community anchor minima may strengthen but never weaken a platform bound:
/// for every platform-listed property the policy must carry an entry with a
/// minimum at or above the platform's (a missing entry counts as weakened
/// to 0).
fn check_not_weakened(
    policy_anchor: &Anchor,
    platform_min: &[AnchorEntry],
) -> Result<(), PolicyError> {
    for bound in platform_min {
        let community_minimum = policy_anchor
            .any_of
            .iter()
            .filter(|e| e.property == bound.property)
            .map(|e| e.minimum)
            .max()
            .unwrap_or(0);
        if community_minimum < bound.minimum {
            return Err(PolicyError::WeakenedAnchor {
                property: bound.property.clone(),
                platform_minimum: bound.minimum,
                community_minimum,
            });
        }
    }
    Ok(())
}

/// Branch-complete anchor validation: every satisfiable permanent branch must
/// entail the permanent anchor, every satisfiable temporal branch the
/// temporal floor; `legal` is refused as anchor and leaf; community minima
/// must not weaken platform bounds; dead expressions and out-of-range minima
/// are rejected.
pub fn validate_policy(
    policy: &AdmissionPolicy,
    platform: &PlatformBounds,
) -> Result<ValidatedPolicy, PolicyError> {
    check_anchor_entries(&policy.permanent_anchor)?;
    check_anchor_entries(&policy.temporal_floor)?;
    check_requirement_leaves(&policy.permanent_if)?;
    if let Some(temporal_if) = &policy.temporal_if {
        check_requirement_leaves(temporal_if)?;
    }
    check_not_weakened(&policy.permanent_anchor, &platform.permanent_anchor_min)?;
    check_not_weakened(&policy.temporal_floor, &platform.temporal_floor_min)?;
    for branch in branches(&policy.permanent_if)? {
        if !branch_entails_anchor(&branch, &policy.permanent_anchor) {
            return Err(PolicyError::UnguardedBranch {
                side: PathSide::Permanent,
            });
        }
    }
    if let Some(temporal_if) = &policy.temporal_if {
        for branch in branches(temporal_if)? {
            if !branch_entails_anchor(&branch, &policy.temporal_floor) {
                return Err(PolicyError::UnguardedBranch {
                    side: PathSide::Temporal,
                });
            }
        }
    }
    if policy.clock.duration_ticks == 0
        || policy.clock.duration_ticks < policy.clock.min_ticks
        || policy.clock.duration_ticks > policy.clock.max_ticks
        || policy.clock.min_ticks > policy.clock.max_ticks
    {
        return Err(PolicyError::BadClock);
    }
    Ok(ValidatedPolicy {
        policy: policy.clone(),
    })
}

/// Which legal scope is red.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegalScope {
    Member,
    Community,
}

/// Inputs to one admission evaluation. All facts are already authenticated;
/// `now` is community-checkpoint time, never a device clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationInput<'a> {
    /// Presented proofs with caller-decided validity flags.
    pub evidence: &'a [Evidence],
    /// Member legality green (no verified applicable member block/burn).
    pub legal_member_green: bool,
    /// Community legality green (no verified applicable community block).
    pub legal_community_green: bool,
    /// Current community-checkpoint tick.
    pub now: Tick,
    /// Tick the current temporal admission started (clock arithmetic base).
    pub admission_start: Tick,
    /// Previously admitted temporal paths that reached their terminal
    /// boundary (spent-path set). Re-entry follows the path's rule, never a
    /// removable exclusion flag.
    pub spent_paths: &'a BTreeSet<String>,
}

/// Why admission was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExclusionReason {
    /// A verified legal block covers the member or the community.
    LegalRed(LegalScope),
    /// Neither the permanent anchor nor the temporal floor is proven by the
    /// corresponding evidence class.
    AnchorUnproven,
    /// Temporal proof holds but the admission clock has run out.
    ClockExpired,
    /// Legal and anchor checks pass but no admission path is satisfied
    /// (expression fails, path spent without re-entry, or evidence lapsed).
    NoSatisfiedPath,
}

/// The membership result: permanent (no admission-clock deadline), on the
/// clock (full member rights until `valid_until`), or excluded. Permanent
/// means no deadline, not immunity from future gates or legal orders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Permanent,
    OnTheClock {
        /// Earliest future boundary at which re-evaluation changes admission:
        /// the minimum over load-bearing evidence expiries and the clock end.
        /// OR branches survive one branch's expiry: a proof whose removal
        /// leaves the membership class unchanged is not load-bearing.
        valid_until: Tick,
    },
    Excluded {
        reason: ExclusionReason,
    },
}

/// Membership class without the deadline (for load-bearing analysis).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MembershipClass {
    Permanent,
    OnTheClock,
    Excluded(ExclusionReason),
}

/// Shared classification over already-usable evidence: legal scopes, then the
/// anchor over the matching evidence classes, then permanent before temporal.
/// Usable evidence is valid and its half-open boundary is still in the future.
fn classify(
    policy: &AdmissionPolicy,
    usable: &[Evidence],
    input: &EvaluationInput<'_>,
) -> MembershipClass {
    if !input.legal_member_green {
        return MembershipClass::Excluded(ExclusionReason::LegalRed(LegalScope::Member));
    }
    if !input.legal_community_green {
        return MembershipClass::Excluded(ExclusionReason::LegalRed(LegalScope::Community));
    }
    let permanent = |p: &Property| score(p, usable, EvidenceClass::Permanent);
    let current = |p: &Property| score(p, usable, EvidenceClass::Current);
    let anchor_proven = policy.permanent_anchor.satisfied(&permanent);
    let floor_proven = policy.temporal_floor.satisfied(&current);
    if !anchor_proven && !floor_proven {
        return MembershipClass::Excluded(ExclusionReason::AnchorUnproven);
    }
    if satisfies(&policy.permanent_if, &permanent) {
        return MembershipClass::Permanent;
    }
    let clock_end = input
        .admission_start
        .saturating_add(policy.clock.duration_ticks);
    let clock_expired = input.now >= clock_end;
    let temporal_satisfied = policy
        .temporal_if
        .as_ref()
        .is_some_and(|req| satisfies(req, &current));
    if !temporal_satisfied {
        return MembershipClass::Excluded(ExclusionReason::NoSatisfiedPath);
    }
    if input.spent_paths.contains(&policy.temporal_path) && !policy.allow_reentry {
        return MembershipClass::Excluded(ExclusionReason::NoSatisfiedPath);
    }
    if clock_expired {
        return MembershipClass::Excluded(ExclusionReason::ClockExpired);
    }
    MembershipClass::OnTheClock
}

/// Evaluate current admission under a validated policy: legal scopes first
/// (either red excludes), then the anchor (neither anchor proven excludes),
/// then the paths (permanent before temporal). The deadline of an
/// on-the-clock admission is the earliest class-changing boundary.
pub fn evaluate(policy: &ValidatedPolicy, input: &EvaluationInput<'_>) -> Admission {
    let policy = policy.policy();
    let usable: Vec<Evidence> = input
        .evidence
        .iter()
        .filter(|e| e.valid && e.valid_until.is_none_or(|end| input.now < end))
        .cloned()
        .collect();
    match classify(policy, &usable, input) {
        MembershipClass::Permanent => Admission::Permanent,
        MembershipClass::Excluded(reason) => Admission::Excluded { reason },
        MembershipClass::OnTheClock => {
            // Earliest future boundary whose crossing changes the membership
            // class: a proof whose removal flips the class is load-bearing.
            // OR branches survive one branch's expiry: a proof whose removal
            // leaves the class unchanged is not load-bearing. The clock end
            // always bounds a temporal admission.
            let clock_end = input
                .admission_start
                .saturating_add(policy.clock.duration_ticks);
            let mut deadline = clock_end;
            for (i, proof) in usable.iter().enumerate() {
                let Some(boundary) = proof.valid_until else {
                    continue;
                };
                if boundary <= input.now {
                    continue;
                }
                let mut without = usable.clone();
                without.remove(i);
                if classify(policy, &without, input) != MembershipClass::OnTheClock {
                    deadline = deadline.min(boundary);
                }
            }
            Admission::OnTheClock {
                valid_until: deadline,
            }
        }
    }
}

/// Trust-bar colour per property: green = required threshold met by current
/// permanent evidence; yellow = met only with unexpired temporal evidence
/// (with its calculated boundary); red = fails, expired, or blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustColor {
    Green,
    Yellow,
    Red,
}

/// Which evidence class carries a trust result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    Permanent,
    Temporal,
    None,
}

/// One property's trust result for the single trust-bar API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustStatus {
    pub color: TrustColor,
    pub evidence: EvidenceKind,
    pub valid_until: Option<Tick>,
}

/// Colour one property check: green by permanent evidence, yellow by temporal
/// evidence with its boundary, red otherwise.
pub fn trust_status(
    required: Strength,
    permanent_score: Strength,
    current_score: Strength,
    temporal_boundary: Option<Tick>,
) -> TrustStatus {
    if permanent_score >= required {
        TrustStatus {
            color: TrustColor::Green,
            evidence: EvidenceKind::Permanent,
            valid_until: None,
        }
    } else if current_score >= required {
        TrustStatus {
            color: TrustColor::Yellow,
            evidence: EvidenceKind::Temporal,
            valid_until: temporal_boundary,
        }
    } else {
        TrustStatus {
            color: TrustColor::Red,
            evidence: EvidenceKind::None,
            valid_until: None,
        }
    }
}

/// A requirement expression evaluated to colours, preserving per-check
/// results and, for OR, the selected branch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustNode {
    Leaf {
        property: Property,
        required: Strength,
        status: TrustStatus,
    },
    /// AND: the worst required colour.
    All {
        children: Vec<TrustNode>,
        color: TrustColor,
    },
    /// OR: the best satisfied branch's colour (`selected` is its index),
    /// or red with no selection when no branch is satisfied.
    Any {
        children: Vec<TrustNode>,
        selected: Option<usize>,
        color: TrustColor,
    },
    /// At least `k` children satisfied: the k-th best child colour,
    /// or red when fewer than `k` are satisfied.
    AtLeast {
        k: usize,
        children: Vec<TrustNode>,
        color: TrustColor,
    },
}

impl TrustNode {
    /// The aggregate colour of this node.
    pub fn color(&self) -> TrustColor {
        match self {
            TrustNode::Leaf { status, .. } => status.color,
            TrustNode::All { color, .. }
            | TrustNode::Any { color, .. }
            | TrustNode::AtLeast { color, .. } => *color,
        }
    }
}

/// Evaluate a requirement expression to a trust tree: per-leaf colours from
/// the permanent/current scores, AND = worst, OR = best satisfied branch,
/// at-least(k) = k-th best when at least k children are satisfied.
pub fn trust_tree(
    req: &Requirement,
    permanent: &dyn Fn(&Property) -> Strength,
    current: &dyn Fn(&Property) -> Strength,
    boundary: &dyn Fn(&Property) -> Option<Tick>,
) -> TrustNode {
    match req {
        Requirement::Property { property, minimum } => TrustNode::Leaf {
            property: property.clone(),
            required: *minimum,
            status: trust_status(
                *minimum,
                permanent(property),
                current(property),
                boundary(property),
            ),
        },
        Requirement::AllOf(children) => {
            let children: Vec<TrustNode> =
                children.iter().map(|c| trust_tree(c, permanent, current, boundary)).collect();
            // AND = worst required colour (Red > Yellow > Green).
            let color = children
                .iter()
                .map(TrustNode::color)
                .max()
                .unwrap_or(TrustColor::Green);
            TrustNode::All { children, color }
        }
        Requirement::AnyOf(children) => {
            let children: Vec<TrustNode> =
                children.iter().map(|c| trust_tree(c, permanent, current, boundary)).collect();
            // OR = best satisfied branch; red with no selection when none is.
            let mut selected: Option<usize> = None;
            let mut color = TrustColor::Red;
            for (i, child) in children.iter().enumerate() {
                let c = child.color();
                if c != TrustColor::Red && (selected.is_none() || c < color) {
                    selected = Some(i);
                    color = c;
                }
            }
            TrustNode::Any {
                children,
                selected,
                color,
            }
        }
        Requirement::AtLeast { k, children } => {
            let children: Vec<TrustNode> =
                children.iter().map(|c| trust_tree(c, permanent, current, boundary)).collect();
            let mut satisfied: Vec<TrustColor> = children
                .iter()
                .map(TrustNode::color)
                .filter(|c| *c != TrustColor::Red)
                .collect();
            satisfied.sort();
            let color = if *k == 0 {
                TrustColor::Green
            } else if satisfied.len() >= *k {
                satisfied[*k - 1]
            } else {
                TrustColor::Red
            };
            TrustNode::AtLeast {
                k: *k,
                children,
                color,
            }
        }
    }
}

/// Legality contributes green/red to authorization (a hidden legal property
/// never exposes an order or invents a public legal-details panel).
pub fn legal_trust(green: bool) -> TrustStatus {
    TrustStatus {
        color: if green {
            TrustColor::Green
        } else {
            TrustColor::Red
        },
        evidence: EvidenceKind::None,
        valid_until: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vouched() -> Property {
        Property::new(PROPERTY_VOUCHED)
    }

    fn personal_property() -> Property {
        Property::new(PROPERTY_VOUCHED_PERSONAL)
    }

    fn admin_property() -> Property {
        Property::new(PROPERTY_VOUCHED_ADMIN)
    }

    fn ev(
        id: &str,
        kind: ProofKind,
        independence: Option<&str>,
        valid: bool,
        valid_until: Option<Tick>,
    ) -> Evidence {
        Evidence {
            id: id.to_string(),
            kind,
            independence: independence.map(str::to_string),
            valid,
            valid_until,
        }
    }

    fn personal(id: &str, key: Option<&str>) -> Evidence {
        ev(id, ProofKind::PersonalVoucher, key, true, None)
    }

    fn admin(id: &str, key: Option<&str>, until: Tick) -> Evidence {
        ev(id, ProofKind::AdminVoucher, key, true, Some(until))
    }

    fn const_scores(pairs: Vec<(Property, Strength)>) -> BTreeMap<Property, Strength> {
        pairs.into_iter().collect()
    }

    fn score_fn(map: &BTreeMap<Property, Strength>) -> impl Fn(&Property) -> Strength + '_ {
        move |p: &Property| map.get(p).copied().unwrap_or(0)
    }

    fn validated_alpha() -> ValidatedPolicy {
        validate_policy(&alpha_policy(), &alpha_platform_bounds())
            .expect("alpha policy validates against alpha bounds")
    }

    fn input<'a>(
        evidence: &'a [Evidence],
        now: Tick,
        admission_start: Tick,
        spent_paths: &'a BTreeSet<String>,
    ) -> EvaluationInput<'a> {
        EvaluationInput {
            evidence,
            legal_member_green: true,
            legal_community_green: true,
            now,
            admission_start,
            spent_paths,
        }
    }

    // ---- §4.1: manifest ----

    #[test]
    fn personal_manifest_is_strong_and_permanent() {
        let m = alpha_manifest(ProofKind::PersonalVoucher);
        assert!(m.permanent, "personal voucher evidence is permanent");
        assert!(
            m.contributions
                .iter()
                .any(|c| c.property == vouched() && c.strength == PERSONAL_VOUCH_STRENGTH),
            "personal voucher establishes vouched strong"
        );
        assert!(
            m.contributions
                .iter()
                .any(|c| c.property == personal_property()),
            "personal voucher establishes vouched.personal"
        );
        assert_eq!(PERSONAL_VOUCH_STRENGTH, STRENGTH_MAX);
    }

    #[test]
    fn admin_manifest_is_weak_and_temporal() {
        let m = alpha_manifest(ProofKind::AdminVoucher);
        assert!(!m.permanent, "admin voucher evidence is temporal");
        assert!(
            m.contributions
                .iter()
                .any(|c| c.property == vouched() && c.strength == ADMIN_VOUCH_STRENGTH),
            "admin voucher establishes vouched weak"
        );
        assert!(
            m.contributions.iter().any(|c| c.property == admin_property()),
            "admin voucher establishes vouched.admin"
        );
        assert!(
            ADMIN_VOUCH_STRENGTH < PERSONAL_VOUCH_STRENGTH,
            "weak is strictly below strong"
        );
    }

    #[test]
    fn manifest_strengths_stay_on_the_fixed_scale() {
        for kind in [ProofKind::PersonalVoucher, ProofKind::AdminVoucher] {
            for c in alpha_manifest(kind).contributions {
                assert!(
                    c.strength <= STRENGTH_MAX,
                    "manifest strength exceeds 0..10000"
                );
            }
        }
    }

    // ---- §4.1: stacking ----

    #[test]
    fn stacking_takes_max_per_component_then_sums() {
        // Same component: personal max wins, no double count.
        let same_component = vec![
            personal("p1", Some("sponsor-a/unit-1")),
            admin("a1", Some("sponsor-a/unit-1"), 9_999_999),
        ];
        assert_eq!(
            score(&vouched(), &same_component, EvidenceClass::Current),
            PERSONAL_VOUCH_STRENGTH
        );
        // Independent components: two weak admins sum.
        let independent = vec![
            admin("a1", Some("role-1/link-1"), 9_999_999),
            admin("a2", Some("role-2/link-2"), 9_999_999),
        ];
        assert_eq!(
            score(&vouched(), &independent, EvidenceClass::Current),
            ADMIN_VOUCH_STRENGTH.saturating_mul(2)
        );
    }

    #[test]
    fn stacking_caps_at_scale_max() {
        let many: Vec<Evidence> = (0..5)
            .map(|i| admin(&format!("a{i}"), Some(&format!("role-{i}/link-{i}")), 9_999_999))
            .collect();
        assert_eq!(
            score(&vouched(), &many, EvidenceClass::Current),
            STRENGTH_MAX,
            "5 x weak would exceed the scale without the cap"
        );
    }

    #[test]
    fn duplicated_proofs_contribute_once() {
        let dupe = vec![
            admin("a1", Some("role-1/link-1"), 9_999_999),
            admin("a1", Some("role-9/link-9"), 9_999_999),
        ];
        assert_eq!(
            score(&vouched(), &dupe, EvidenceClass::Current),
            ADMIN_VOUCH_STRENGTH,
            "same proof id in another component still counts once"
        );
    }

    #[test]
    fn unknown_independence_merges_into_one_component() {
        let unknown = vec![
            admin("a1", None, 9_999_999),
            admin("a2", None, 9_999_999),
        ];
        assert_eq!(
            score(&vouched(), &unknown, EvidenceClass::Current),
            ADMIN_VOUCH_STRENGTH,
            "missing independence metadata is never presumed independent"
        );
    }

    #[test]
    fn components_are_evaluated_per_property() {
        let mixed = vec![
            personal("p1", Some("sponsor-a/unit-1")),
            admin("a1", Some("sponsor-a/unit-1"), 9_999_999),
        ];
        assert_eq!(
            score(&personal_property(), &mixed, EvidenceClass::Current),
            PERSONAL_VOUCH_STRENGTH
        );
        assert_eq!(
            score(&admin_property(), &mixed, EvidenceClass::Current),
            ADMIN_VOUCH_STRENGTH
        );
        // An admin voucher never raises the personal property.
        assert_eq!(
            score(
                &personal_property(),
                &vec![admin("a1", Some("role-1/link-1"), 9_999_999)],
                EvidenceClass::Current
            ),
            0,
            "cross-property evidence must not add to the wrong property"
        );
    }

    #[test]
    fn permanent_scores_exclude_temporal_evidence() {
        let admin_only = vec![admin("a1", Some("role-1/link-1"), 9_999_999)];
        assert_eq!(
            score(&vouched(), &admin_only, EvidenceClass::Permanent),
            0,
            "temporal evidence never counts as permanent"
        );
        let personal_only = vec![personal("p1", Some("sponsor-a/unit-1"))];
        assert_eq!(
            score(&vouched(), &personal_only, EvidenceClass::Permanent),
            PERSONAL_VOUCH_STRENGTH
        );
        assert_eq!(
            score(&vouched(), &admin_only, EvidenceClass::Current),
            ADMIN_VOUCH_STRENGTH,
            "current scores also use valid temporal evidence"
        );
    }

    #[test]
    fn invalid_proofs_score_zero() {
        let revoked = vec![ev(
            "a1",
            ProofKind::AdminVoucher,
            Some("role-1/link-1"),
            false,
            Some(9_999_999),
        )];
        assert_eq!(
            score(&vouched(), &revoked, EvidenceClass::Current),
            0,
            "revoked/expired proofs contribute nothing"
        );
        assert_eq!(
            score(&vouched(), &[], EvidenceClass::Current),
            0,
            "empty evidence scores zero"
        );
    }

    // ---- §4.2: requirement expressions ----

    #[test]
    fn leaf_holds_at_exact_minimum() {
        let req = Requirement::Property {
            property: vouched(),
            minimum: 100,
        };
        let at = const_scores(vec![(vouched(), 100)]);
        assert!(satisfies(&req, &score_fn(&at)));
        let below = const_scores(vec![(vouched(), 99)]);
        assert!(!satisfies(&req, &score_fn(&below)));
    }

    #[test]
    fn all_any_at_least_semantics() {
        let leaf = |min: Strength| Requirement::Property {
            property: vouched(),
            minimum: min,
        };
        let scores = const_scores(vec![(vouched(), 50)]);
        let f = score_fn(&scores);
        assert!(satisfies(&Requirement::AllOf(vec![leaf(10), leaf(50)]), &f));
        assert!(!satisfies(&Requirement::AllOf(vec![leaf(10), leaf(51)]), &f));
        assert!(satisfies(&Requirement::AnyOf(vec![leaf(51), leaf(50)]), &f));
        assert!(!satisfies(&Requirement::AnyOf(vec![leaf(51), leaf(52)]), &f));
        let two_of_three = Requirement::AtLeast {
            k: 2,
            children: vec![leaf(50), leaf(50), leaf(51)],
        };
        assert!(satisfies(&two_of_three, &f));
        let one_met = Requirement::AtLeast {
            k: 2,
            children: vec![leaf(50), leaf(51), leaf(52)],
        };
        assert!(!satisfies(&one_met, &f));
    }

    #[test]
    fn unknown_properties_are_not_satisfied_by_default() {
        let req = Requirement::Property {
            property: Property::new("future-module.some-claim"),
            minimum: 1,
        };
        let empty = const_scores(vec![]);
        assert!(!satisfies(&req, &score_fn(&empty)));
    }

    // ---- §4.2: anchor validation ----

    #[test]
    fn alpha_policy_validates_against_alpha_bounds() {
        let policy = alpha_policy();
        let bounds = alpha_platform_bounds();
        assert!(validate_policy(&policy, &bounds).is_ok());
    }

    #[test]
    fn unguarded_or_branch_is_rejected() {
        let mut policy = alpha_policy();
        policy.permanent_if = Requirement::AnyOf(vec![
            Requirement::Property {
                property: vouched(),
                minimum: STRENGTH_MAX,
            },
            Requirement::Property {
                property: admin_property(),
                minimum: 1,
            },
        ]);
        assert_eq!(
            validate_policy(&policy, &alpha_platform_bounds()),
            Err(PolicyError::UnguardedBranch {
                side: PathSide::Permanent
            }),
            "an OR branch entailing no anchor must be rejected"
        );
    }

    #[test]
    fn temporal_branch_must_entail_the_floor() {
        let mut policy = alpha_policy();
        policy.temporal_if = Some(Requirement::AnyOf(vec![
            Requirement::Property {
                property: vouched(),
                minimum: ADMIN_VOUCH_STRENGTH,
            },
            Requirement::Property {
                property: admin_property(),
                minimum: 1,
            },
        ]));
        assert_eq!(
            validate_policy(&policy, &alpha_platform_bounds()),
            Err(PolicyError::UnguardedBranch {
                side: PathSide::Temporal
            })
        );
    }

    #[test]
    fn legal_is_never_an_anchor_or_a_leaf() {
        let mut policy = alpha_policy();
        policy.permanent_anchor = Anchor {
            any_of: vec![AnchorEntry {
                property: Property::new(PROPERTY_LEGAL),
                minimum: 1,
            }],
        };
        assert_eq!(
            validate_policy(&policy, &alpha_platform_bounds()),
            Err(PolicyError::LegalNeverAnchor)
        );
        let mut leafy = alpha_policy();
        leafy.permanent_if = Requirement::Property {
            property: Property::new(PROPERTY_LEGAL),
            minimum: 1,
        };
        assert_eq!(
            validate_policy(&leafy, &alpha_platform_bounds()),
            Err(PolicyError::LegalNotScored)
        );
    }

    #[test]
    fn community_may_strengthen_but_not_weaken_the_anchor() {
        let mut weakened = alpha_policy();
        weakened.permanent_anchor = Anchor {
            any_of: vec![AnchorEntry {
                property: vouched(),
                minimum: PERSONAL_VOUCH_STRENGTH - 1,
            }],
        };
        // The permanent branch still requires strong, but the anchor entry
        // itself weakens the platform bound: rejected.
        weakened.permanent_if = Requirement::Property {
            property: vouched(),
            minimum: PERSONAL_VOUCH_STRENGTH - 1,
        };
        assert!(matches!(
            validate_policy(&weakened, &alpha_platform_bounds()),
            Err(PolicyError::WeakenedAnchor { .. })
        ));
        // Strengthening above the platform bound is allowed.
        let bounds = PlatformBounds {
            permanent_anchor_min: vec![AnchorEntry {
                property: vouched(),
                minimum: ADMIN_VOUCH_STRENGTH,
            }],
            temporal_floor_min: vec![AnchorEntry {
                property: vouched(),
                minimum: ADMIN_VOUCH_STRENGTH,
            }],
        };
        assert!(validate_policy(&alpha_policy(), &bounds).is_ok());
    }

    #[test]
    fn vacuous_and_dead_expressions_are_rejected() {
        let mut policy = alpha_policy();
        policy.permanent_if = Requirement::AtLeast {
            k: 0,
            children: vec![Requirement::Property {
                property: vouched(),
                minimum: STRENGTH_MAX,
            }],
        };
        assert_eq!(
            validate_policy(&policy, &alpha_platform_bounds()),
            Err(PolicyError::UnguardedBranch {
                side: PathSide::Permanent
            }),
            "at_least(0) is always true and entails no anchor"
        );
        policy.permanent_if = Requirement::AllOf(vec![]);
        assert_eq!(
            validate_policy(&policy, &alpha_platform_bounds()),
            Err(PolicyError::UnguardedBranch {
                side: PathSide::Permanent
            }),
            "empty all_of is always true and entails no anchor"
        );
        policy.permanent_if = Requirement::AnyOf(vec![]);
        assert_eq!(
            validate_policy(&policy, &alpha_platform_bounds()),
            Err(PolicyError::UnsatisfiableRequirement)
        );
        policy.permanent_if = Requirement::AtLeast {
            k: 3,
            children: vec![Requirement::Property {
                property: vouched(),
                minimum: 1,
            }],
        };
        assert_eq!(
            validate_policy(&policy, &alpha_platform_bounds()),
            Err(PolicyError::UnsatisfiableRequirement)
        );
    }

    #[test]
    fn out_of_range_minima_are_rejected() {
        let mut policy = alpha_policy();
        policy.permanent_if = Requirement::Property {
            property: vouched(),
            minimum: STRENGTH_MAX + 1,
        };
        assert_eq!(
            validate_policy(&policy, &alpha_platform_bounds()),
            Err(PolicyError::StrengthOutOfRange)
        );
        policy = alpha_policy();
        policy.permanent_anchor = Anchor {
            any_of: vec![AnchorEntry {
                property: vouched(),
                minimum: STRENGTH_MAX + 1,
            }],
        };
        assert_eq!(
            validate_policy(&policy, &alpha_platform_bounds()),
            Err(PolicyError::StrengthOutOfRange)
        );
    }

    #[test]
    fn empty_anchor_is_rejected() {
        let mut policy = alpha_policy();
        policy.permanent_anchor = Anchor { any_of: vec![] };
        assert_eq!(
            validate_policy(&policy, &alpha_platform_bounds()),
            Err(PolicyError::EmptyAnchor)
        );
    }

    // ---- §4.3: membership ----

    #[test]
    fn personal_voucher_is_permanent() {
        let policy = validated_alpha();
        let evidence = vec![personal("p1", Some("sponsor-a/unit-1"))];
        let spent = BTreeSet::new();
        assert_eq!(
            evaluate(&policy, &input(&evidence, 1_000_000, 900_000, &spent)),
            Admission::Permanent,
            "personal voucher satisfies the anchor: permanent, no clock"
        );
    }

    #[test]
    fn admin_voucher_is_on_the_clock_with_deadline() {
        let policy = validated_alpha();
        let evidence = vec![admin("a1", Some("role-1/link-1"), 1_500_000)];
        let spent = BTreeSet::new();
        assert_eq!(
            evaluate(&policy, &input(&evidence, 1_000_000, 900_000, &spent)),
            Admission::OnTheClock {
                valid_until: 1_500_000
            },
            "admin voucher is weak: full member on the clock"
        );
    }

    #[test]
    fn no_evidence_is_excluded_for_unproven_anchor() {
        let policy = validated_alpha();
        let spent = BTreeSet::new();
        assert_eq!(
            evaluate(&policy, &input(&[], 1_000_000, 900_000, &spent)),
            Admission::Excluded {
                reason: ExclusionReason::AnchorUnproven
            }
        );
    }

    #[test]
    fn legal_red_excludes_despite_personal_proof() {
        let policy = validated_alpha();
        let evidence = vec![personal("p1", Some("sponsor-a/unit-1"))];
        let spent = BTreeSet::new();
        let mut member_red = input(&evidence, 1_000_000, 900_000, &spent);
        member_red.legal_member_green = false;
        assert_eq!(
            evaluate(&policy, &member_red),
            Admission::Excluded {
                reason: ExclusionReason::LegalRed(LegalScope::Member)
            }
        );
        let mut community_red = input(&evidence, 1_000_000, 900_000, &spent);
        community_red.legal_community_green = false;
        assert_eq!(
            evaluate(&policy, &community_red),
            Admission::Excluded {
                reason: ExclusionReason::LegalRed(LegalScope::Community)
            }
        );
    }

    #[test]
    fn lapsed_temporal_evidence_is_excluded() {
        let policy = validated_alpha();
        // Flagged invalid (revoked link): contributes nothing.
        let revoked = vec![ev(
            "a1",
            ProofKind::AdminVoucher,
            Some("role-1/link-1"),
            false,
            Some(1_500_000),
        )];
        let spent = BTreeSet::new();
        assert!(matches!(
            evaluate(&policy, &input(&revoked, 1_000_000, 900_000, &spent)),
            Admission::Excluded { .. }
        ));
        // Boundary passed even with the flag set: half-open expiry wins.
        let past_boundary = vec![admin("a1", Some("role-1/link-1"), 900_000)];
        assert!(matches!(
            evaluate(&policy, &input(&past_boundary, 1_000_000, 900_000, &spent)),
            Admission::Excluded { .. }
        ));
    }

    #[test]
    fn expired_clock_excludes_with_reason() {
        let policy = validated_alpha();
        let evidence = vec![admin("a1", Some("role-1/link-1"), 9_999_999)];
        let spent = BTreeSet::new();
        // Clock: start 900_000 + 2_102_400 = 3_002_400; now is past it.
        assert_eq!(
            evaluate(&policy, &input(&evidence, 3_002_400, 900_000, &spent)),
            Admission::Excluded {
                reason: ExclusionReason::ClockExpired
            }
        );
    }

    #[test]
    fn spent_temporal_path_blocks_reentry_by_default() {
        let policy = validated_alpha();
        assert!(!policy.policy().allow_reentry);
        let evidence = vec![admin("a1", Some("role-1/link-1"), 9_999_999)];
        let spent: BTreeSet<String> = [ALPHA_TEMPORAL_PATH.to_string()].into_iter().collect();
        assert_eq!(
            evaluate(&policy, &input(&evidence, 1_000_000, 900_000, &spent)),
            Admission::Excluded {
                reason: ExclusionReason::NoSatisfiedPath
            }
        );
    }

    #[test]
    fn stacked_admin_vouchers_stay_temporal_below_a_personal_proof() {
        // Four independent weak admins reach the anchor numerically, but the
        // evidence is temporal: still on the clock, never permanent.
        let policy = validated_alpha();
        let evidence: Vec<Evidence> = (0..4)
            .map(|i| admin(&format!("a{i}"), Some(&format!("role-{i}/link-{i}")), 9_999_999))
            .collect();
        assert_eq!(
            score(&vouched(), &evidence, EvidenceClass::Current),
            STRENGTH_MAX
        );
        let spent = BTreeSet::new();
        assert!(matches!(
            evaluate(&policy, &input(&evidence, 1_000_000, 900_000, &spent)),
            Admission::OnTheClock { .. }
        ));
    }

    #[test]
    fn personal_proof_upgrades_an_admin_clock_to_permanent() {
        let policy = validated_alpha();
        let evidence = vec![
            personal("p1", Some("sponsor-a/unit-1")),
            admin("a1", Some("role-1/link-1"), 1_500_000),
        ];
        let spent = BTreeSet::new();
        assert_eq!(
            evaluate(&policy, &input(&evidence, 1_000_000, 900_000, &spent)),
            Admission::Permanent,
            "a sufficient personal proof wins over the temporal path"
        );
    }

    #[test]
    fn deadline_is_the_earliest_class_changing_boundary() {
        // Custom policy needing two weak admins: losing either flips the
        // class, so the deadline is the earlier expiry.
        let mut policy = alpha_policy();
        policy.temporal_if = Some(Requirement::Property {
            property: vouched(),
            minimum: ADMIN_VOUCH_STRENGTH * 2,
        });
        let policy = validate_policy(&policy, &alpha_platform_bounds())
            .expect("custom temporal policy validates");
        let evidence = vec![
            admin("a1", Some("role-1/link-1"), 1_200_000),
            admin("a2", Some("role-2/link-2"), 1_800_000),
        ];
        let spent = BTreeSet::new();
        assert_eq!(
            evaluate(&policy, &input(&evidence, 1_000_000, 900_000, &spent)),
            Admission::OnTheClock {
                valid_until: 1_200_000
            }
        );
    }

    #[test]
    fn or_branches_survive_one_branch_expiry() {
        // Alpha floor needs one weak admin: with two independent ones, either
        // expiry alone leaves the class unchanged, so the deadline is the
        // clock end, not the first expiry.
        let policy = validated_alpha();
        let evidence = vec![
            admin("a1", Some("role-1/link-1"), 1_200_000),
            admin("a2", Some("role-2/link-2"), 1_800_000),
        ];
        let spent = BTreeSet::new();
        assert_eq!(
            evaluate(&policy, &input(&evidence, 1_000_000, 900_000, &spent)),
            Admission::OnTheClock {
                valid_until: 900_000 + ALPHA_CLOCK_TICKS
            }
        );
    }

    // ---- §4.3: trust bar ----

    #[test]
    fn trust_colours_follow_evidence_class() {
        assert_eq!(
            trust_status(STRENGTH_MAX, STRENGTH_MAX, STRENGTH_MAX, None),
            TrustStatus {
                color: TrustColor::Green,
                evidence: EvidenceKind::Permanent,
                valid_until: None
            }
        );
        assert_eq!(
            trust_status(STRENGTH_MAX, 0, STRENGTH_MAX, Some(1_500_000)),
            TrustStatus {
                color: TrustColor::Yellow,
                evidence: EvidenceKind::Temporal,
                valid_until: Some(1_500_000)
            },
            "yellow carries the calculated boundary"
        );
        assert_eq!(
            trust_status(STRENGTH_MAX, 0, 0, None),
            TrustStatus {
                color: TrustColor::Red,
                evidence: EvidenceKind::None,
                valid_until: None
            }
        );
    }

    #[test]
    fn trust_and_is_worst() {
        let req = Requirement::AllOf(vec![
            Requirement::Property {
                property: vouched(),
                minimum: 1,
            },
            Requirement::Property {
                property: personal_property(),
                minimum: 1,
            },
        ]);
        // Permanent vouched only: children Green + Red.
        let perm = const_scores(vec![(vouched(), 10)]);
        let curr = const_scores(vec![(vouched(), 10)]);
        let no_boundary = |_: &Property| None;
        let tree = trust_tree(&req, &score_fn(&perm), &score_fn(&curr), &no_boundary);
        assert_eq!(tree.color(), TrustColor::Red);
        // Temporal personal too: children Green + Yellow -> Yellow.
        let curr2 = const_scores(vec![(vouched(), 10), (personal_property(), 10)]);
        let tree2 = trust_tree(&req, &score_fn(&perm), &score_fn(&curr2), &no_boundary);
        assert_eq!(tree2.color(), TrustColor::Yellow);
    }

    #[test]
    fn trust_or_is_best_satisfied_branch() {
        let req = Requirement::AnyOf(vec![
            Requirement::Property {
                property: personal_property(),
                minimum: 1,
            },
            Requirement::Property {
                property: vouched(),
                minimum: 1,
            },
        ]);
        // First branch red, second yellow: best satisfied wins with selection.
        let perm = const_scores(vec![]);
        let curr = const_scores(vec![(vouched(), 10)]);
        let boundary = |_: &Property| Some(1_500_000);
        let tree = trust_tree(&req, &score_fn(&perm), &score_fn(&curr), &boundary);
        assert_eq!(tree.color(), TrustColor::Yellow);
        match tree {
            TrustNode::Any {
                selected: Some(1),
                ..
            } => {}
            other => panic!("OR must select the satisfied branch, got {other:?}"),
        }
        // Nothing satisfied: red with no selection, results preserved.
        let none = const_scores(vec![]);
        let tree_none = trust_tree(&req, &score_fn(&none), &score_fn(&none), &boundary);
        assert_eq!(tree_none.color(), TrustColor::Red);
        match tree_none {
            TrustNode::Any {
                selected: None,
                children,
                ..
            } => assert_eq!(children.len(), 2),
            other => panic!("unsatisfied OR keeps per-check results, got {other:?}"),
        }
    }

    #[test]
    fn trust_at_least_needs_k_satisfied() {
        let req = Requirement::AtLeast {
            k: 2,
            children: vec![
                Requirement::Property {
                    property: vouched(),
                    minimum: 1,
                },
                Requirement::Property {
                    property: personal_property(),
                    minimum: 1,
                },
                Requirement::Property {
                    property: admin_property(),
                    minimum: 1,
                },
            ],
        };
        // Green + Yellow + Red: two satisfied, k-th best is Yellow.
        let perm = const_scores(vec![(vouched(), 10)]);
        let curr = const_scores(vec![
            (vouched(), 10),
            (personal_property(), 10),
            (admin_property(), 0),
        ]);
        let boundary = |_: &Property| Some(1_500_000);
        let tree = trust_tree(&req, &score_fn(&perm), &score_fn(&curr), &boundary);
        assert_eq!(tree.color(), TrustColor::Yellow);
        // Only one satisfied: red.
        let curr_one = const_scores(vec![(vouched(), 10)]);
        let tree_one = trust_tree(&req, &score_fn(&perm), &score_fn(&curr_one), &boundary);
        assert_eq!(tree_one.color(), TrustColor::Red);
    }

    #[test]
    fn legality_contributes_green_or_red() {
        assert_eq!(
            legal_trust(true),
            TrustStatus {
                color: TrustColor::Green,
                evidence: EvidenceKind::None,
                valid_until: None
            }
        );
        assert_eq!(legal_trust(false).color, TrustColor::Red);
    }
}
