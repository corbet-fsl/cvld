//! Opaque registered recipient and actual target-Policy creation entitlement.
use super::*;
use crate::auth::{Auth, creation::RootCreationSession};
use crate::service::Context;

pub(super) struct Recipient {
    session: admission::AdmissionSession,
    id: String,
    pub(super) until: u64,
    deadline: std::time::Instant,
}
pub(crate) struct Created {
    value: CommunityCreationInvitation,
    session: admission::AdmissionSession,
    snapshot: cplc::VerifiedSnapshot,
    deadline: std::time::Instant,
}
impl CommunityService {
    pub(crate) fn link_creation_owner(&mut self, owner: Arc<()>) -> Result<()> {
        if self
            .creation_owner
            .as_ref()
            .is_some_and(|old| !Arc::ptr_eq(old, &owner))
        {
            return Err(Error::Forbidden);
        }
        self.creation_owner = Some(owner);
        Ok(())
    }
    pub(crate) async fn creation_recipient(
        &mut self,
        ctx: &Context,
        request: CreationRecipientRequest,
    ) -> Result<CreationRecipient> {
        self.creation_owner.as_ref().ok_or(Error::Unavailable)?;
        let session = self.admission_session(ctx)?;
        let started = std::time::Instant::now();
        let now = self.clock.now();
        session.release(now)?;
        self.prune(now);
        if self.creation_recipients.len() >= self.config.pending_capacity {
            return Err(Error::Throttled);
        }
        let mut policy = self.facade.policy().lock().await;
        let snapshot = policy
            .verified_settings(now)
            .await
            .map_err(Error::Refused.redact())?;
        let cap = cmbr::RoleSession::valid_until(&session).min(snapshot.valid_until());
        if request.expires_at <= now || request.expires_at > cap {
            return Err(Error::Invalid);
        }
        crate::service::publication::expires_at(request.expires_at)?;
        let deadline = started
            .checked_add(std::time::Duration::from_secs(request.expires_at - now))
            .ok_or(Error::Invalid)?;
        let id = match request.id {
            Some(id) => ckyh::Uuid::parse_str(&id).map_err(Error::Invalid.redact())?,
            None => ckyh::Uuid::new_v4(),
        }
        .to_string();
        let row = self
            .facade
            .membership()
            .resume(&session.authentication)
            .await
            .map_err(Error::Refused.redact())?;
        if row.state().is_terminal() || row.state() == cmbr::State::Started {
            return Err(Error::Refused);
        }
        let completed = self.clock.now();
        session.release(completed)?;
        policy
            .validate_snapshot(&snapshot, completed)
            .await
            .map_err(Error::Refused.redact())?;
        session.release(self.clock.now())?;
        if std::time::Instant::now() >= deadline {
            return Err(Error::Unauthorized);
        }
        let recipient = token();
        self.creation_recipients.insert(
            recipient.clone(),
            Recipient {
                session,
                id: id.clone(),
                until: request.expires_at,
                deadline,
            },
        );
        Ok(CreationRecipient {
            recipient,
            id,
            expires_at: request.expires_at,
        })
    }

    pub(crate) async fn initialize_creation(
        &mut self,
        recipient: &str,
        owner: &Arc<()>,
        root: &mut RootCreationSession,
        auth: &mut Auth,
        token: &str,
        root_clock: &dyn Clock,
    ) -> Result<Created> {
        if !self
            .creation_owner
            .as_ref()
            .is_some_and(|actual| Arc::ptr_eq(actual, owner))
        {
            return Err(Error::Forbidden);
        }
        // Move this one-use capability into the future. Cancellation cannot
        // restore or swap it; fresh authorization may retry the original terms.
        let pending = self
            .creation_recipients
            .remove(recipient)
            .ok_or(Error::Refused)?;
        let observed = self.clock.now();
        pending.session.release(observed)?;
        if observed >= pending.until || std::time::Instant::now() >= pending.deadline {
            return Err(Error::Refused);
        }
        let mut policy = self.facade.policy().lock().await;
        let snapshot = policy
            .verified_settings(observed)
            .await
            .map_err(Error::Refused.redact())?;
        if pending.until > snapshot.valid_until() {
            return Err(Error::Refused);
        }
        let row = self
            .facade
            .membership()
            .resume(&pending.session.authentication)
            .await
            .map_err(Error::Refused.redact())?;
        let member = row.subject();
        let receipt = cvch::receipt_id(&pending.id);
        let binding = cvch::member_binding(&receipt, member.as_bytes());
        root.check(auth, token, root_clock).await?;
        let issued = self.clock.now();
        pending.session.release(issued)?;
        if issued >= pending.until {
            return Err(Error::Refused);
        }
        let invitation = policy
            .issue_role_invitation(&cvch::role::Invitation {
                id: &pending.id,
                community: &self.config.community,
                member_binding: &binding,
                purpose: cvch::role::Purpose::BootstrapRoot,
                issued_at: issued,
                valid_until: pending.until,
            })
            .await
            .map_err(Error::Refused.redact())?;
        let verified = cvch::role::verify(
            &invitation,
            policy.key_ring().map_err(Error::Refused.redact())?,
            &cvch::role::Context {
                community: &self.config.community,
                member: member.as_bytes(),
                purpose: cvch::role::Purpose::BootstrapRoot,
                now: issued,
            },
        )
        .map_err(Error::Refused.redact())?;
        let mut guard = Producer {
            root,
            auth,
            token,
            root_clock,
            policy: &policy,
            snapshot: &snapshot,
            invitation: &invitation,
            deadline: pending.deadline,
        };
        self.facade
            .membership()
            .initialize_community_creation_checked(
                cmbr::CreationRequest {
                    invitation: &verified,
                    authentication: &pending.session.authentication,
                    session: &pending.session,
                },
                &mut guard,
            )
            .await
            .map_err(|error| {
                if error == cmbr::Error::Unavailable {
                    Error::Reconcile
                } else {
                    Error::Refused
                }
            })?;
        let completed = self.clock.now();
        pending.session.release(completed)?;
        let root_floor = guard
            .root
            .check(guard.auth, token, root_clock)
            .await
            .map_err(|e| {
                eprintln!("DIAG cr {e:?} line={}", line!());
                Error::Reconcile
            })?;
        let checked_at = self.clock.now();
        pending.session.release(checked_at)?;
        if checked_at < completed.max(root_floor) || checked_at >= pending.until {
            {
                eprintln!("DIAG cret line={}", line!());
                return Err(Error::Reconcile);
            }
        }
        Ok(Created {
            value: CommunityCreationInvitation {
                invitation,
                id: pending.id,
                expires_at: pending.until,
                checked_at,
            },
            session: pending.session,
            snapshot,
            deadline: pending.deadline,
        })
    }

    pub(crate) async fn release_creation(
        &self,
        mut created: Created,
        floor: u64,
    ) -> Result<Created> {
        let now = self.clock.now();
        if now < floor.max(created.value.checked_at)
            || now >= created.value.expires_at
            || std::time::Instant::now() >= created.deadline
        {
            {
                eprintln!("DIAG cret line={}", line!());
                return Err(Error::Reconcile);
            }
        }
        created.session.release(now)?;
        let policy = self.facade.policy().lock().await;
        policy
            .validate_snapshot(&created.snapshot, now)
            .await
            .map_err(|e| {
                eprintln!("DIAG cr {e:?} line={}", line!());
                Error::Reconcile
            })?;
        if !self
            .facade
            .membership()
            .session_is_active(
                &created.session.authentication,
                created.session.authentication.credential_id(),
            )
            .await
            .map_err(|e| {
                eprintln!("DIAG cr {e:?} line={}", line!());
                Error::Reconcile
            })?
        {
            {
                eprintln!("DIAG cret line={}", line!());
                return Err(Error::Reconcile);
            }
        }
        let completed = self.clock.now();
        created.session.release(completed)?;
        if completed < now || completed >= created.value.expires_at {
            {
                eprintln!("DIAG cret line={}", line!());
                return Err(Error::Reconcile);
            }
        }
        created.value.checked_at = completed;
        Ok(created)
    }
    pub(crate) fn project_creation(
        &self,
        mut created: Created,
        floor: u64,
    ) -> Result<CommunityCreationInvitation> {
        let now = self.clock.now();
        if now < floor.max(created.value.checked_at)
            || now >= created.value.expires_at
            || std::time::Instant::now() >= created.deadline
        {
            {
                eprintln!("DIAG cret line={}", line!());
                return Err(Error::Reconcile);
            }
        }
        created.session.release(now)?;
        created.value.checked_at = now;
        Ok(created.value)
    }
}

struct Producer<'a> {
    root: &'a mut RootCreationSession,
    auth: &'a mut Auth,
    token: &'a str,
    root_clock: &'a dyn Clock,
    policy: &'a cplc::Policy<Rules, cplc::LibsqlStore, csgn::LibsqlStore>,
    snapshot: &'a cplc::VerifiedSnapshot,
    invitation: &'a [u8],
    deadline: std::time::Instant,
}
impl cmbr::CreationGuard for Producer<'_> {
    async fn check(
        &mut self,
        context: &cmbr::CreationContext<'_>,
        observed: u64,
    ) -> cmbr::Result<()> {
        if std::time::Instant::now() >= self.deadline {
            eprintln!("DIAG producer deadline");
            return Err(cmbr::Error::Transition);
        }
        self.root
            .check(self.auth, self.token, self.root_clock)
            .await
            .map_err(|e| {
                eprintln!("DIAG producer root check {e:?}");
                cmbr::Error::Identity
            })?;
        self.policy
            .validate_snapshot(self.snapshot, observed)
            .await
            .map_err(|_| cmbr::Error::Policy)?;
        let verified = cvch::role::verify(
            self.invitation,
            self.policy.key_ring().map_err(|_| cmbr::Error::Policy)?,
            &cvch::role::Context {
                community: context.community(),
                member: context.member(),
                purpose: cvch::role::Purpose::BootstrapRoot,
                now: observed,
            },
        )
        .map_err(|_| cmbr::Error::Policy)?;
        if verified.receipt() != context.receipt()
            || verified.binding() != context.binding()
            || verified.valid_until() != context.expires_at()
        {
            return Err(cmbr::Error::Identity);
        }
        Ok(())
    }
    fn release(&mut self, _: &cmbr::CreationContext<'_>, observed: u64) -> cmbr::Result<()> {
        if std::time::Instant::now() >= self.deadline {
            return Err(cmbr::Error::Transition);
        }
        if self
            .root
            .release(self.auth, self.token, self.root_clock)
            .map_err(|e| {
                eprintln!("DIAG producer root release {e:?}");
                cmbr::Error::Identity
            })?
            != observed
        {
            eprintln!("DIAG producer release mismatch observed={observed}");
            return Err(cmbr::Error::Transition);
        }
        Ok(())
    }
}
