//! Server-side enforcement of the gates in force. A member who has not passed
//! the community gates now in force is held in the lobby: every action not
//! declared `lobby` in the registry is refused with `HeldInLobby`, and the
//! device maps that refusal to the lobby. Gates that need a fresh global
//! passport cannot be judged here (nothing global is cached) and stay out.

use super::*;
use crate::api::{LobbyLevel, LobbyMissing};

/// Whether the unmet conditions include a community-level gate group.
pub(super) fn is_held(missing: &[LobbyMissing]) -> bool {
    missing.iter().any(|item| match item {
        // A membership state still to be reached is settled by credential issue itself.
        LobbyMissing::ActionUnavailable | LobbyMissing::Membership { .. } => false,
        LobbyMissing::Gates {
            needed,
            alternatives,
        } => {
            *needed > 0
                && !alternatives.is_empty()
                && alternatives
                    .iter()
                    .all(|gate| matches!(gate.requirement.level, LobbyLevel::Community))
        }
    })
}

impl CommunityService {
    /// Refuse a held member. Errors of the check itself are not hidden.
    pub(crate) async fn refuse_if_held(&self, auth: &ckyh::Authentication, now: u64) -> Result<()> {
        let lobby = self.lobby(auth, now).await?;
        if is_held(&lobby.missing) {
            return Err(Error::HeldInLobby);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{LobbyGate, LobbyMembership, LobbyReason, LobbyRequirement};

    fn gates(levels: &[LobbyLevel], needed: usize) -> LobbyMissing {
        LobbyMissing::Gates {
            needed,
            alternatives: levels
                .iter()
                .map(|level| LobbyGate {
                    requirement: LobbyRequirement {
                        gate: "g".into(),
                        level: match level {
                            LobbyLevel::Global => LobbyLevel::Global,
                            LobbyLevel::Community => LobbyLevel::Community,
                        },
                        provider: None,
                    },
                    reason: LobbyReason::ProofRequired,
                })
                .collect(),
        }
    }

    #[test]
    fn only_unmet_community_gates_hold() {
        assert!(!is_held(&[]));
        assert!(!is_held(&[LobbyMissing::ActionUnavailable]));
        assert!(!is_held(&[LobbyMissing::Membership {
            allowed: vec![LobbyMembership::Admitted]
        }]));
        assert!(is_held(&[gates(&[LobbyLevel::Community], 1)]));
        assert!(!is_held(&[gates(&[LobbyLevel::Global], 1)]));
        assert!(!is_held(&[gates(
            &[LobbyLevel::Community, LobbyLevel::Global],
            1
        )]));
        assert!(!is_held(&[gates(&[LobbyLevel::Community], 0)]));
    }

    /// Default held: the exemptions are exactly the marked actions, and no
    /// unmarked member action can ever run for a held member.
    #[test]
    fn registry_marks_decide_what_a_held_member_may_call() {
        use crate::api::{ACTIONS, Access};
        let exempt: Vec<&str> = ACTIONS
            .iter()
            .filter(|a| a.access == Access::Member && a.lobby)
            .map(|a| a.name)
            .collect();
        for needed in [
            "lobby",
            "handle_reserve",
            "voucher_redeem",
            "voucher_reply_get",
            "gate_withdraw",
        ] {
            assert!(exempt.contains(&needed), "{needed}");
        }
        for held in [
            "credential_issue",
            "account_credential_issue",
            "account",
            "account_enroll",
            "pin_set",
            "pin_get",
            "pin_change",
            "payment_execute",
            "voucher_link_create",
            "member_role",
        ] {
            let action = ACTIONS.iter().find(|a| a.name == held).unwrap();
            assert!(!action.lobby, "{held} must be held by default");
        }
        // Admin actions never lock an admin out of the portal.
        assert!(
            ACTIONS
                .iter()
                .filter(|a| a.access == Access::Admin)
                .all(|a| a.lobby)
        );
    }
}
