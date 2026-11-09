//! The door's errors: the contract types of `cvld-client`, plus the server-only mapping of
//! membership failures.
pub use cvld_client::error::*;

/// Server-side redaction of a failed membership call.
pub trait MembershipRedact {
    /// Like `redact_at` for a failed membership call: a transient condition (busy row, failed
    /// storage or infrastructure) is `Unavailable` (503, the device retries) and never the
    /// permanent category of the call site; every other failure keeps `self`.
    fn redact_membership_at(self, site: &'static str) -> impl FnOnce(cmty::cmbr::Error) -> Error;
}

impl MembershipRedact for Error {
    fn redact_membership_at(self, site: &'static str) -> impl FnOnce(cmty::cmbr::Error) -> Error {
        move |cause| match cause {
            cmty::cmbr::Error::Unavailable | cmty::cmbr::Error::Busy => {
                Error::Unavailable.redact_at(site)(cause)
            }
            _ => self.redact_at(site)(cause),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transient membership condition (busy store, failed infrastructure) is never reported as
    /// the permanent category of its call site: it stays 503 so the device retries.
    #[test]
    fn a_transient_membership_failure_stays_unavailable() {
        for transient in [cmty::cmbr::Error::Unavailable, cmty::cmbr::Error::Busy] {
            let err = Error::Unauthorized.redact_membership_at("probe")(transient);
            assert_eq!(err, Error::Unavailable);
            assert_eq!(err.http_status(), 503);
        }
        let err = Error::Unauthorized.redact_membership_at("probe")(cmty::cmbr::Error::Transition);
        assert_eq!(err, Error::Unauthorized);
        let err = Error::Refused.redact_membership_at("probe")(cmty::cmbr::Error::Identity);
        assert_eq!(err, Error::Refused);
    }
}
