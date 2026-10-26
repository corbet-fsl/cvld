//! Membership clocks and exits as pure derivation over facts plus a tick.
//!
//! Decided state (STATUS.md rows dated 2026-10-26; design is subordinate to
//! them, PLAN-state-model-2026-10-26.md):
//!
//! - An admin-pool admission puts the member on the clock: the duration is a
//!   community setting, default 365 days, platform range 30..=365 days. Every
//!   admitted person is a full member; some memberships are on the clock.
//!   There are no guests (L1576).
//! - A personal invite within the clock makes the member permanent: permanent
//!   means no admission-clock deadline, not immunity from future gates or
//!   legal orders (L1576, L1596).
//! - When the clock runs out the member is excluded, with no re-entry via
//!   the same path; re-entry is itself a community setting, default blocked
//!   (L1576-L1577: exclusion and no re-entry are the defaults, not fixed
//!   rules).
//! - An event admission runs until the event ends plus one day (community
//!   setting), then the member is excluded (L1576-L1577).
//! - When an admin is demoted for abuse, the members they admitted from the
//!   admin pool get a shorter clock: the remaining time capped at 30 days
//!   (community setting with platform bounds). Unused links of that admin
//!   die immediately. A normal (non-abuse) demotion keeps the remaining
//!   time by default; the community setting may choose a restart instead
//!   (L1621, Anna story E; supersedes the earlier "back on probation with
//!   the same timeout").
//! - A demotion-triggered restart happens at most once per member; after that
//!   only a personal invite makes the member permanent (L1599, Q3). The
//!   once-only budget is moot for abuse demotions, which shorten rather than
//!   restart (L1621).
//!
//! Mechanics (M): everything here is derived from an ordered fact slice plus
//! the current community tick. There are no timers, no cleanup jobs, no TTLs.
//! Every interval is half-open `[start, end)`: equality with `end` means the
//! clock has run out. Facts dated after `now` are not facts yet and are
//! ignored. Same-tick facts fold in slice order, which is the canonical
//! agreed sequence. Multi-sponsor corners not decided in STATUS are marked M
//! below: a further admin admission while already on the clock records the
//! sponsor (so a later demotion of that admin still bites) but starts no new
//! path, so re-invites cannot stretch the clock; a fresh event admission
//! after an exclusion starts a new episode, because each event is its own
//! path while the re-entry block governs the admin pool.
//!
//! Out of scope: legality (clbs), voucher allowance/accounting, and the
//! trust-bar display, which only reads the status derived here.

/// Community slot length in seconds (DESIGN-state-model-2026-10-26 §2).
pub const TICK_SECONDS: u64 = 15;

/// Ticks per community day. 86_400 is an exact multiple of 15, so day
/// durations need no rounding to whole ticks.
pub const TICKS_PER_DAY: u64 = 24 * 3_600 / TICK_SECONDS;

const _: () = assert!(24 * 3_600 % TICK_SECONDS == 0);

/// Default admin-pool clock: 365 days (L1576).
pub const DEFAULT_CLOCK_DAYS: u32 = 365;
/// Platform range for the community clock setting: 30..=365 days (L1576).
pub const MIN_CLOCK_DAYS: u32 = 30;
pub const MAX_CLOCK_DAYS: u32 = 365;
/// Default event overhang past the event end: 1 day (L1577).
pub const DEFAULT_EVENT_EXTRA_DAYS: u32 = 1;
/// Platform range for the event-overhang setting (M choice).
pub const MAX_EVENT_EXTRA_DAYS: u32 = 30;
/// Default abuse-demotion cap: 30 days (L1621).
pub const DEFAULT_ABUSE_CAP_DAYS: u32 = 30;
/// Platform range for the abuse-demotion cap setting (M choice).
pub const MIN_ABUSE_CAP_DAYS: u32 = 1;
pub const MAX_ABUSE_CAP_DAYS: u32 = 365;

/// What a normal (non-abuse) demotion of a sponsor does to the clocks of
/// that admin's still-dependent invitees. Default is [`NormalDemotion::Keep`]
/// (L1621); the community may choose `Restart` instead, subject to the
/// once-only rule (L1599).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NormalDemotion {
    /// The clock keeps running with the remaining time.
    KeepRemaining,
    /// The clock restarts with the full community duration, at most once
    /// per member per clock episode.
    Restart,
}

/// Community settings for membership clocks. Values in the STATUS rows are
/// defaults and bounds, not fixed rules (L1577).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockPolicy {
    /// Admin-pool clock duration in days, 30..=365.
    pub clock_days: u32,
    /// Event overhang past the event end in days, 0..=30.
    pub event_extra_days: u32,
    /// Abuse-demotion cap in days, 1..=365.
    pub abuse_cap_days: u32,
    /// Normal-demotion behaviour.
    pub normal_demotion: NormalDemotion,
    /// Block re-entry via the admin-pool path after a clock expiry.
    pub block_same_path_reentry: bool,
}

impl Default for ClockPolicy {
    fn default() -> Self {
        ClockPolicy {
            clock_days: DEFAULT_CLOCK_DAYS,
            event_extra_days: DEFAULT_EVENT_EXTRA_DAYS,
            abuse_cap_days: DEFAULT_ABUSE_CAP_DAYS,
            normal_demotion: NormalDemotion::KeepRemaining,
            block_same_path_reentry: true,
        }
    }
}

/// A community clock setting outside its platform bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    ClockDaysOutOfRange { days: u32 },
    EventExtraOutOfRange { days: u32 },
    AbuseCapOutOfRange { days: u32 },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            PolicyError::ClockDaysOutOfRange { days } => write!(
                f,
                "clock_days {days} outside {MIN_CLOCK_DAYS}..={MAX_CLOCK_DAYS}"
            ),
            PolicyError::EventExtraOutOfRange { days } => {
                write!(f, "event_extra_days {days} outside 0..={MAX_EVENT_EXTRA_DAYS}")
            }
            PolicyError::AbuseCapOutOfRange { days } => write!(
                f,
                "abuse_cap_days {days} outside {MIN_ABUSE_CAP_DAYS}..={MAX_ABUSE_CAP_DAYS}"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

impl ClockPolicy {
    /// Check the community settings against the platform bounds.
    pub fn validate(&self) -> Result<(), PolicyError> {
        todo!("P3c red: validate not implemented yet")
    }

    fn clock_ticks(&self) -> u64 {
        u64::from(self.clock_days) * TICKS_PER_DAY
    }

    fn event_extra_ticks(&self) -> u64 {
        u64::from(self.event_extra_days) * TICKS_PER_DAY
    }

    fn abuse_cap_ticks(&self) -> u64 {
        u64::from(self.abuse_cap_days) * TICKS_PER_DAY
    }
}

/// Opaque member and admin identifiers. The caller maps its own identity
/// types onto these; only equality is used.
pub type MemberId = u64;
pub type AdminId = u64;

/// Signed base facts consumed by the clock fold, in canonical agreed order.
/// Only facts with `tick <= now` are folded; later facts are not facts yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fact {
    /// Admission from an admin pool: starts (or records a sponsor of) the
    /// member's clock.
    AdminAdmitted {
        member: MemberId,
        admin: AdminId,
        tick: u64,
    },
    /// Admission for an event: valid until `event_end` plus the community
    /// overhang. `event` distinguishes event paths from each other.
    EventAdmitted {
        member: MemberId,
        event: u64,
        tick: u64,
        event_end: u64,
    },
    /// A personal invite: the permanent path. Makes the member permanent
    /// from this tick on, including after a temporal exclusion, because the
    /// re-entry block covers only the same (temporal) path.
    PersonalInvited { member: MemberId, tick: u64 },
    /// A sponsor's role ended. Applies only to that admin's still-dependent
    /// invitees; permanent members and already-excluded members are
    /// untouched.
    AdminDemoted {
        admin: AdminId,
        tick: u64,
        for_abuse: bool,
    },
}

impl Fact {
    fn tick(&self) -> u64 {
        match *self {
            Fact::AdminAdmitted { tick, .. }
            | Fact::EventAdmitted { tick, .. }
            | Fact::PersonalInvited { tick, .. }
            | Fact::AdminDemoted { tick, .. } => tick,
        }
    }

    fn member(&self) -> Option<MemberId> {
        match *self {
            Fact::AdminAdmitted { member, .. }
            | Fact::EventAdmitted { member, .. }
            | Fact::PersonalInvited { member, .. } => Some(member),
            Fact::AdminDemoted { .. } => None,
        }
    }
}

/// Why a member left the clocked state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// The temporal clock ran out: `now` reached the half-open deadline.
    ClockExpired,
}

/// Membership time status derived from facts plus the current tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// No temporal admission on record (and no personal invite): the member
    /// is not in through any clocked path.
    Absent,
    /// Permanent: no admission-clock deadline. A personal invite, whenever
    /// it arrived, is sticky (L1596).
    Permanent,
    /// On the clock with full member rights until `deadline`; valid while
    /// `now < deadline` (L1576).
    OnClock { deadline: u64 },
    /// Excluded after the clock ran out (L1576).
    Excluded { reason: ExitReason },
}

/// One temporal path with its own half-open expiry. A member is on the clock
/// while any path is unexpired; the reported deadline is the earliest future
/// expiry, i.e. the next boundary at which re-evaluation changes admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Path {
    expiry: u64,
    sponsor: Option<AdminId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Fold {
    Absent,
    OnClock {
        paths: Vec<Path>,
        sponsors: Vec<AdminId>,
        restart_used: bool,
    },
    Permanent,
    Excluded,
}

impl Fold {
    fn admit_admin(&mut self, policy: &ClockPolicy, admin: AdminId, tick: u64) {
        match self {
            Fold::Absent => {
                *self = Fold::OnClock {
                    paths: vec![Path {
                        expiry: tick.saturating_add(policy.clock_ticks()),
                        sponsor: Some(admin),
                    }],
                    sponsors: vec![admin],
                    restart_used: false,
                };
            }
            Fold::Excluded => {
                if !policy.block_same_path_reentry {
                    *self = Fold::OnClock {
                        paths: vec![Path {
                            expiry: tick.saturating_add(policy.clock_ticks()),
                            sponsor: Some(admin),
                        }],
                        sponsors: vec![admin],
                        restart_used: false,
                    };
                }
            }
            Fold::OnClock { sponsors, .. } => {
                // M: record the sponsor for later demotion attribution, but
                // start no new path, so re-invites cannot stretch the clock.
                if !sponsors.contains(&admin) {
                    sponsors.push(admin);
                }
            }
            Fold::Permanent => {}
        }
    }

    fn admit_event(&mut self, policy: &ClockPolicy, event_end: u64) {
        let expiry = event_end.saturating_add(policy.event_extra_ticks());
        match self {
            // M: each event is its own path, so a fresh event admission
            // after an exclusion starts a new episode; the re-entry block
            // governs the admin-pool path only.
            Fold::Absent | Fold::Excluded => {
                *self = Fold::OnClock {
                    paths: vec![Path {
                        expiry,
                        sponsor: None,
                    }],
                    sponsors: Vec::new(),
                    restart_used: false,
                };
            }
            Fold::OnClock { paths, .. } => {
                paths.push(Path {
                    expiry,
                    sponsor: None,
                });
            }
            Fold::Permanent => {}
        }
    }

    fn demote(&mut self, policy: &ClockPolicy, admin: AdminId, tick: u64, for_abuse: bool) {
        let Fold::OnClock {
            paths,
            sponsors,
            restart_used,
        } = self
        else {
            return;
        };
        if !sponsors.contains(&admin) {
            return;
        }
        if for_abuse {
            // L1621: remaining time capped at the abuse cap. The once-only
            // restart budget is moot here: shortening is not restarting.
            let cap = tick.saturating_add(policy.abuse_cap_ticks());
            for path in paths.iter_mut().filter(|p| p.sponsor == Some(admin)) {
                path.expiry = path.expiry.min(cap);
            }
        } else if policy.normal_demotion == NormalDemotion::Restart && !*restart_used {
            // L1599: at most one demotion-triggered restart per episode.
            for path in paths.iter_mut().filter(|p| p.sponsor == Some(admin)) {
                path.expiry = tick.saturating_add(policy.clock_ticks());
            }
            *restart_used = true;
        }
    }

    fn status(&self, now: u64) -> Status {
        match self {
            Fold::Absent => Status::Absent,
            Fold::Permanent => Status::Permanent,
            Fold::Excluded => Status::Excluded {
                reason: ExitReason::ClockExpired,
            },
            Fold::OnClock { paths, .. } => {
                match paths.iter().map(|p| p.expiry).filter(|e| *e > now).min() {
                    Some(deadline) => Status::OnClock { deadline },
                    None => Status::Excluded {
                        reason: ExitReason::ClockExpired,
                    },
                }
            }
        }
    }
}

/// Derive a member's time status from the community clock settings, the
/// signed facts, and the current community tick.
///
/// Facts must be given in canonical agreed order; same-tick facts fold in
/// slice order. Facts dated after `now` are ignored.
pub fn evaluate(
    policy: &ClockPolicy,
    member: MemberId,
    facts: &[Fact],
    now: u64,
) -> Result<Status, PolicyError> {
    policy.validate()?;
    let _ = (member, facts, now);
    todo!("P3c red: evaluate not implemented yet")
}

/// Whether an unused admin-pool link is still redeemable at `now`.
///
/// Links are half-open like clocks, and any demotion of the issuing admin
/// ends that admin's unused links immediately (L1598, L1621): members
/// already admitted through the link keep their (possibly shortened) clock,
/// but the link itself redeems nothing from the demotion tick on.
pub fn admin_link_usable(
    issued_tick: u64,
    expires_tick: u64,
    issuer_demoted_at: Option<u64>,
    now: u64,
) -> bool {
    let _ = (issued_tick, expires_tick, issuer_demoted_at, now);
    todo!("P3c red: admin_link_usable not implemented yet")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = TICKS_PER_DAY;
    const MEMBER: MemberId = 7;
    const ADMIN: AdminId = 1;
    const OTHER_ADMIN: AdminId = 2;

    fn policy() -> ClockPolicy {
        ClockPolicy::default()
    }

    fn admin_admitted(tick: u64) -> Fact {
        Fact::AdminAdmitted {
            member: MEMBER,
            admin: ADMIN,
            tick,
        }
    }

    fn at(policy: &ClockPolicy, facts: &[Fact], now: u64) -> Status {
        evaluate(policy, MEMBER, facts, now).expect("valid test policy")
    }

    #[test]
    fn admin_pool_admission_starts_default_365_day_clock() {
        let t0 = 10 * DAY;
        let facts = [admin_admitted(t0)];
        // Half-open [t0, t0 + 365d): valid at admission, excluded at deadline.
        assert_eq!(
            at(&policy(), &facts, t0),
            Status::OnClock {
                deadline: t0 + 365 * DAY
            }
        );
        assert_eq!(
            at(&policy(), &facts, t0 + 365 * DAY - 1),
            Status::OnClock {
                deadline: t0 + 365 * DAY
            }
        );
        assert_eq!(
            at(&policy(), &facts, t0 + 365 * DAY),
            Status::Excluded {
                reason: ExitReason::ClockExpired
            }
        );
    }

    #[test]
    fn clock_duration_is_a_community_setting_within_30_to_365() {
        let short = ClockPolicy {
            clock_days: 30,
            ..policy()
        };
        let t0 = 3 * DAY;
        let facts = [admin_admitted(t0)];
        assert_eq!(
            at(&short, &facts, t0 + 30 * DAY - 1),
            Status::OnClock {
                deadline: t0 + 30 * DAY
            }
        );
        assert_eq!(
            at(&short, &facts, t0 + 30 * DAY),
            Status::Excluded {
                reason: ExitReason::ClockExpired
            }
        );
        for days in [0, 29, 366, 10_000] {
            let bad = ClockPolicy {
                clock_days: days,
                ..policy()
            };
            assert_eq!(
                bad.validate(),
                Err(PolicyError::ClockDaysOutOfRange { days }),
                "clock_days = {days}"
            );
            assert!(evaluate(&bad, MEMBER, &facts, t0).is_err());
        }
        for days in [30, 31, 364, 365] {
            assert!(ClockPolicy {
                clock_days: days,
                ..policy()
            }
            .validate()
            .is_ok());
        }
    }

    #[test]
    fn personal_invite_within_clock_makes_permanent() {
        let t0 = 10 * DAY;
        let invite = t0 + 100 * DAY;
        let facts = [
            admin_admitted(t0),
            Fact::PersonalInvited {
                member: MEMBER,
                tick: invite,
            },
        ];
        assert_eq!(at(&policy(), &facts, invite), Status::Permanent);
        // Permanent is sticky: still permanent past the old deadline.
        assert_eq!(at(&policy(), &facts, t0 + 365 * DAY), Status::Permanent);
        assert_eq!(at(&policy(), &facts, t0 + 1_000 * DAY), Status::Permanent);
    }

    #[test]
    fn no_reentry_via_same_path_after_expiry_by_default() {
        let t0 = 10 * DAY;
        let expired = t0 + 365 * DAY;
        let facts = [admin_admitted(t0), admin_admitted(expired + DAY)];
        assert_eq!(
            at(&policy(), &facts, expired + DAY),
            Status::Excluded {
                reason: ExitReason::ClockExpired
            }
        );
    }

    #[test]
    fn open_reentry_setting_starts_a_fresh_clock() {
        let open = ClockPolicy {
            block_same_path_reentry: false,
            ..policy()
        };
        let t0 = 10 * DAY;
        let readmit = t0 + 365 * DAY + DAY;
        let facts = [admin_admitted(t0), admin_admitted(readmit)];
        assert_eq!(
            at(&open, &facts, readmit),
            Status::OnClock {
                deadline: readmit + 365 * DAY
            }
        );
    }

    #[test]
    fn event_admission_runs_to_end_plus_one_day() {
        let end = 50 * DAY;
        let facts = [Fact::EventAdmitted {
            member: MEMBER,
            event: 9,
            tick: 40 * DAY,
            event_end: end,
        }];
        assert_eq!(
            at(&policy(), &facts, end + DAY - 1),
            Status::OnClock {
                deadline: end + DAY
            }
        );
        assert_eq!(
            at(&policy(), &facts, end + DAY),
            Status::Excluded {
                reason: ExitReason::ClockExpired
            }
        );
    }

    #[test]
    fn abuse_demotion_caps_invitees_at_min_remaining_30_days() {
        let t0 = 10 * DAY;
        let demote = t0 + 100 * DAY;
        let facts = [
            admin_admitted(t0),
            Fact::AdminDemoted {
                admin: ADMIN,
                tick: demote,
                for_abuse: true,
            },
        ];
        // Long remaining time is shortened to demotion + 30 days.
        assert_eq!(
            at(&policy(), &facts, demote),
            Status::OnClock {
                deadline: demote + 30 * DAY
            }
        );
        assert_eq!(
            at(&policy(), &facts, demote + 30 * DAY),
            Status::Excluded {
                reason: ExitReason::ClockExpired
            }
        );

        // Short remaining time is kept: min() never stretches a clock.
        let late = t0 + 350 * DAY;
        let facts = [
            admin_admitted(t0),
            Fact::AdminDemoted {
                admin: ADMIN,
                tick: late,
                for_abuse: true,
            },
        ];
        assert_eq!(
            at(&policy(), &facts, late),
            Status::OnClock {
                deadline: t0 + 365 * DAY
            }
        );
    }

    #[test]
    fn normal_demotion_keeps_remaining_time_by_default() {
        let t0 = 10 * DAY;
        let demote = t0 + 100 * DAY;
        let facts = [
            admin_admitted(t0),
            Fact::AdminDemoted {
                admin: ADMIN,
                tick: demote,
                for_abuse: false,
            },
        ];
        assert_eq!(
            at(&policy(), &facts, demote),
            Status::OnClock {
                deadline: t0 + 365 * DAY
            }
        );
    }

    #[test]
    fn clock_restart_happens_at_most_once() {
        let restart = ClockPolicy {
            normal_demotion: NormalDemotion::Restart,
            ..policy()
        };
        let t0 = 10 * DAY;
        let first = t0 + 300 * DAY;
        let second = first + 100 * DAY;
        let facts = [
            admin_admitted(t0),
            Fact::AdminDemoted {
                admin: ADMIN,
                tick: first,
                for_abuse: false,
            },
            Fact::AdminDemoted {
                admin: ADMIN,
                tick: second,
                for_abuse: false,
            },
        ];
        // First demotion restarts with the full duration from the demotion.
        assert_eq!(
            at(&restart, &facts[..2], first),
            Status::OnClock {
                deadline: first + 365 * DAY
            }
        );
        // Second demotion restarts nothing: the first deadline stands.
        assert_eq!(
            at(&restart, &facts, second),
            Status::OnClock {
                deadline: first + 365 * DAY
            }
        );
    }

    #[test]
    fn personal_invite_after_expiry_admits_via_the_personal_path() {
        // The re-entry block covers the same (temporal) path only; a
        // personal invite is the permanent path.
        let t0 = 10 * DAY;
        let expired = t0 + 365 * DAY;
        let invite = expired + 5 * DAY;
        let facts = [
            admin_admitted(t0),
            Fact::PersonalInvited {
                member: MEMBER,
                tick: invite,
            },
        ];
        assert_eq!(at(&policy(), &facts, expired), Status::Permanent);
        assert_eq!(at(&policy(), &facts, invite), Status::Permanent);
    }

    #[test]
    fn abuse_demotion_kills_unused_links_without_spending_the_restart() {
        let issued = 10 * DAY;
        let expires = issued + 90 * DAY;
        let demote = 20 * DAY;
        assert!(admin_link_usable(issued, expires, None, demote - 1));
        // From the demotion tick on the link redeems nothing.
        assert!(!admin_link_usable(issued, expires, Some(demote), demote));
        assert!(!admin_link_usable(issued, expires, Some(demote), demote + 1));
        // Half-open link validity is untouched otherwise.
        assert!(!admin_link_usable(issued, expires, None, issued - 1));
        assert!(!admin_link_usable(issued, expires, None, expires));

        // Shortening is not restarting: a later normal demotion under the
        // Restart setting still restarts once.
        let restart = ClockPolicy {
            normal_demotion: NormalDemotion::Restart,
            ..policy()
        };
        let t0 = 10 * DAY;
        let abuse = t0 + 100 * DAY;
        let normal = abuse + 10 * DAY;
        let facts = [
            admin_admitted(t0),
            Fact::AdminDemoted {
                admin: ADMIN,
                tick: abuse,
                for_abuse: true,
            },
            Fact::AdminDemoted {
                admin: ADMIN,
                tick: normal,
                for_abuse: false,
            },
        ];
        assert_eq!(
            at(&restart, &facts, normal),
            Status::OnClock {
                deadline: normal + 365 * DAY
            }
        );
    }

    #[test]
    fn unrelated_demotions_and_permanent_members_are_untouched() {
        let t0 = 10 * DAY;
        let demote = t0 + 100 * DAY;
        // Demotion of an admin who never admitted this member: no effect.
        let facts = [
            admin_admitted(t0),
            Fact::AdminDemoted {
                admin: OTHER_ADMIN,
                tick: demote,
                for_abuse: true,
            },
        ];
        assert_eq!(
            at(&policy(), &facts, demote),
            Status::OnClock {
                deadline: t0 + 365 * DAY
            }
        );
        // A permanent member ignores even their own sponsor's abuse demotion.
        let facts = [
            admin_admitted(t0),
            Fact::PersonalInvited {
                member: MEMBER,
                tick: t0 + DAY,
            },
            Fact::AdminDemoted {
                admin: ADMIN,
                tick: demote,
                for_abuse: true,
            },
        ];
        assert_eq!(at(&policy(), &facts, demote), Status::Permanent);
        // A demotion after the clock already expired changes nothing.
        let facts = [
            admin_admitted(t0),
            Fact::AdminDemoted {
                admin: ADMIN,
                tick: t0 + 400 * DAY,
                for_abuse: false,
            },
        ];
        assert_eq!(
            at(&policy(), &facts, t0 + 400 * DAY),
            Status::Excluded {
                reason: ExitReason::ClockExpired
            }
        );
    }

    #[test]
    fn future_facts_are_not_facts_yet() {
        let t0 = 10 * DAY;
        let facts = [
            admin_admitted(t0),
            Fact::AdminDemoted {
                admin: ADMIN,
                tick: t0 + 500 * DAY,
                for_abuse: true,
            },
            Fact::PersonalInvited {
                member: MEMBER,
                tick: t0 + 600 * DAY,
            },
        ];
        assert_eq!(
            at(&policy(), &facts, t0),
            Status::OnClock {
                deadline: t0 + 365 * DAY
            }
        );
    }

    #[test]
    fn second_admin_admission_records_sponsor_without_stretching() {
        // M: a re-invite while on the clock records the new sponsor (so
        // that admin's later demotion still bites) but starts no new path.
        let t0 = 10 * DAY;
        let second = t0 + 300 * DAY;
        let demote = second + 10 * DAY;
        let facts = [
            admin_admitted(t0),
            Fact::AdminAdmitted {
                member: MEMBER,
                admin: OTHER_ADMIN,
                tick: second,
            },
            Fact::AdminDemoted {
                admin: OTHER_ADMIN,
                tick: demote,
                for_abuse: true,
            },
        ];
        // The clock still ends at the original deadline absent demotion ...
        assert_eq!(
            at(&policy(), &facts[..2], second),
            Status::OnClock {
                deadline: t0 + 365 * DAY
            }
        );
        // ... and the second sponsor's abuse demotion shortens it.
        assert_eq!(
            at(&policy(), &facts, demote),
            Status::OnClock {
                deadline: demote + 30 * DAY
            }
        );
    }

    #[test]
    fn member_without_facts_is_absent_and_other_members_do_not_leak() {
        assert_eq!(at(&policy(), &[], 100 * DAY), Status::Absent);
        let facts = [Fact::AdminAdmitted {
            member: 999,
            admin: ADMIN,
            tick: 10 * DAY,
        }];
        assert_eq!(at(&policy(), &facts, 100 * DAY), Status::Absent);
        // A personal invite alone (no temporal admission) is permanent.
        let facts = [Fact::PersonalInvited {
            member: MEMBER,
            tick: 10 * DAY,
        }];
        assert_eq!(at(&policy(), &facts, 10 * DAY), Status::Permanent);
    }
}
