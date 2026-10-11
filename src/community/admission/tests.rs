//! Actual originating sessions, current membership writer and late release cuts.
use super::*;
use crate::community::root_issuance_tests::fixture::world;
use crate::test_support::*;
use cmbr::RoleSession as _;

const HOST: &str = "api.alpha.example.test";

fn context(owner: &CommunityService, bearer: &str) -> Context {
    let session = owner.sessions.get(bearer).unwrap();
    Context {
        host: HOST.into(),
        token: Some(bearer.into()),
        grant: Some(session.grant.clone()),
        authentication: Some(session.authentication.clone()),
        now: NOW,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_exact_original_member_session_can_be_captured() {
    let world = world().await;
    let mut owner = world.source.door.community_backend().unwrap().lock().await;
    assert!(owner.accounts.is_none());
    let mut ctx = context(&owner, &world.member.session);
    let session = owner.admission_session(&ctx).unwrap();
    let auth = ctx.authentication.as_ref().unwrap().clone();
    ctx.authentication = Some(Arc::new(auth.as_ref().clone()));
    assert!(matches!(
        owner.admission_session(&ctx),
        Err(Error::Unauthorized)
    ));
    ctx.authentication = Some(auth);
    ctx.token = None;
    assert!(matches!(
        owner.admission_session(&ctx),
        Err(Error::Unauthorized)
    ));
    ctx.token = Some(world.garden.clone());
    assert!(matches!(
        owner.admission_session(&ctx),
        Err(Error::Unauthorized)
    ));
    ctx.token = Some(world.member.session.clone());
    ctx.host = "api.admin.alpha.example.test".into();
    assert!(matches!(
        owner.admission_session(&ctx),
        Err(Error::Unauthorized)
    ));
    let current = owner.sessions.get_mut(&world.member.session).unwrap();
    current.authority = session_authority::Owner::default();
    assert!(matches!(session.release(NOW), Err(Error::Reconcile)));
    let renewed = owner
        .admission_session(&context(&owner, &world.member.session))
        .unwrap();
    assert!(renewed.release(NOW).is_ok());
    owner.logout(&world.member.session);
    assert!(matches!(renewed.release(NOW), Err(Error::Reconcile)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_owner_commit_floor_survives_the_awaited_host_return() {
    let world = world().await;
    let owner = world.source.door.community_backend().unwrap().lock().await;
    let session = Arc::new(
        owner
            .admission_session(&context(&owner, &world.member.session))
            .unwrap(),
    );
    let auth = session.authentication.clone();
    let membership = owner.facade.membership().clone();
    let lease = membership.role(&auth).await.unwrap();
    let member = lease.member().to_owned();
    assert_eq!(lease.role(), cmbr::Role::Root);
    drop(lease);
    // Original Register initialized this fixture's preexisting Root. This real
    // owner mutation exercises the exact retained session callback, not a claim
    // that a role invitation or fake device verdict grants first admission.
    world.source.clock.set(NOW + 20);
    crate::service::with_live_clock(membership.set_member_role_checked(
        &auth,
        &member,
        cmbr::Role::Admin,
        NOW,
        session.valid_until(),
        session.clone(),
    ))
    .await
    .unwrap();
    assert!(session.observed.load(Ordering::Acquire) >= NOW + 20);
    world.source.clock.set(NOW + 15);
    assert!(matches!(
        session.release(owner.clock.now()),
        Err(Error::Reconcile)
    ));
    // Fresh observation cannot revive the poisoned result, or undo the actual
    // already committed role. The original retained credential remains genuine.
    world.source.clock.set(NOW + 21);
    assert!(matches!(
        session.release(owner.clock.now()),
        Err(Error::Reconcile)
    ));
    let lease = crate::service::with_live_clock(membership.role(&auth))
        .await
        .unwrap();
    assert_eq!(lease.role(), cmbr::Role::Admin);
}

struct Completing {
    actual: Arc<AdmissionSession>,
    entries: std::sync::atomic::AtomicUsize,
    entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}
impl cmbr::RoleSession for Completing {
    fn valid_until(&self) -> u64 {
        self.actual.valid_until()
    }
    fn check(&self, authentication: &ckyh::Authentication, observed: u64) -> cmbr::Result<()> {
        self.actual.check(authentication, observed)?;
        // Observe the original explicit host and completing-entry calls. Every
        // authority decision still comes from the exact real stored session.
        if self.entries.fetch_add(1, Ordering::SeqCst) == 1
            && let Some(sender) = self.entered.lock().unwrap().take()
        {
            let _ = sender.send(());
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_current_writer_retains_the_original_session_until_actual_logout() {
    let world = world().await;
    let mut owner = world.source.door.community_backend().unwrap().lock().await;
    let session = Arc::new(
        owner
            .admission_session(&context(&owner, &world.member.session))
            .unwrap(),
    );
    let auth = session.authentication.clone();
    let membership = owner.facade.membership().clone();
    let lease = membership.role(&auth).await.unwrap();
    let member = lease.member().to_owned();
    assert_eq!(lease.role(), cmbr::Role::Root);
    drop(lease);
    let held = owner.db.community("alpha").unwrap().tx().await.unwrap();
    let (entered, received) = tokio::sync::oneshot::channel();
    let completing = Arc::new(Completing {
        actual: session.clone(),
        entries: Default::default(),
        entered: std::sync::Mutex::new(Some(entered)),
    });
    let mut request = Box::pin(membership.set_member_role_checked(
        &auth,
        &member,
        cmbr::Role::Admin,
        NOW,
        session.valid_until(),
        completing.clone(),
    ));
    tokio::select! {
        result = &mut request => panic!("unexpected early completion: {result:?}"),
        result = received => result.unwrap(),
    }
    drop(request);
    assert!(Arc::strong_count(&completing) > 1);
    owner.logout(&world.member.session);
    held.rollback().await.unwrap();
    let lease = tokio::time::timeout(std::time::Duration::from_secs(5), membership.role(&auth))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.role(), cmbr::Role::Root);
    assert_eq!(Arc::strong_count(&completing), 1);
    assert!(matches!(session.release(NOW), Err(Error::Reconcile)));
}
