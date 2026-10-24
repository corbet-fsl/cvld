//! Announced settings changes that are not yet in force, as the lobby shows them.
//! A newcomer sees ahead of time which values will change and when; the lobby
//! never reveals who set them or why.

use crate::api::LobbyUpcoming;
use cmty::cplc::crbk;

/// Cap on announced revisions the lobby looks through.
pub(super) const LOOKAHEAD: usize = 8;

/// Every setting whose resolved value differs between the rulebook in force and
/// each announced revision, in effect order. A later revision is compared with
/// the one before it, so a value changed twice is listed twice.
pub(super) fn changes(
    current: &crbk::Rulebook,
    pending: &[crbk::Revision],
) -> Result<Vec<LobbyUpcoming>, crbk::Error> {
    let mut before = current.describe()?;
    let mut out = Vec::new();
    for revision in pending {
        let after = revision.change.rulebook.describe()?;
        for view in &after {
            let Some(old) = before.iter().find(|v| v.key == view.key) else {
                continue;
            };
            if old.effective != view.effective {
                out.push(LobbyUpcoming {
                    key: view.key.clone(),
                    label: view.meta.label.clone(),
                    from: old.effective.clone(),
                    to: view.effective.clone(),
                    effective_at: revision.change.effective_at,
                });
            }
        }
        before = after;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn book(days: i64) -> crbk::Rulebook {
        let mut book = crbk::Rulebook::default();
        crbk::define_platform_settings(&mut book).unwrap();
        book.set_community("waves.waiting_period_days", Some(days.into()))
            .unwrap();
        book
    }

    fn revision(number: u64, days: i64, effective_at: i64) -> crbk::Revision {
        crbk::Revision {
            revision: number,
            change: crbk::Change {
                rulebook: book(days),
                announced_at: 0,
                effective_at,
                notice_seconds: 0,
                policy_epoch: 1,
            },
        }
    }

    #[test]
    fn lists_only_changed_values_in_effect_order() {
        let pending = [revision(2, 14, 1_000), revision(3, 21, 2_000)];
        let out = changes(&book(7), &pending).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].key, "waves.waiting_period_days");
        assert_eq!(
            (out[0].from.as_i64(), out[0].to.as_i64()),
            (Some(7), Some(14))
        );
        assert_eq!(out[0].effective_at, 1_000);
        assert_eq!(
            (out[1].from.as_i64(), out[1].to.as_i64()),
            (Some(14), Some(21))
        );
        assert!(
            changes(&book(7), &[revision(2, 7, 1_000)])
                .unwrap()
                .is_empty()
        );
        assert!(changes(&book(7), &[]).unwrap().is_empty());
    }
}
