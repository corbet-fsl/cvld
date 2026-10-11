//! The real host session owner remains authoritative without native accounts.
use super::*;
use cmbr::RoleSession as _;

mod foreign;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_garden_role_change_and_session_replacement_need_no_account_runtime() {
    let world = world().await;
    let garden = client(&world.source, GARDEN, Some(&world.garden));
    let role: MemberRole =
        serde_json::from_value(garden.call("member_role", json!({})).await.unwrap()).unwrap();
    garden
        .call(
            "member_role_set",
            json!({"member":role.member,"role":"admin"}),
        )
        .await
        .unwrap();
    let changed: MemberRole =
        serde_json::from_value(garden.call("member_role", json!({})).await.unwrap()).unwrap();
    assert_eq!(changed.role, Role::Admin);
    let mut owner = world.source.door.community_backend().unwrap().lock().await;
    assert!(owner.accounts.is_none());
    let current = owner.sessions.get(&world.garden).unwrap();
    let auth = current.authentication.clone();
    let original =
        current
            .authority
            .role_lease(auth.clone(), current.grant.clone(), current.started);
    assert!(original.check(&auth, NOW).is_ok());
    assert!(original.check(&auth, current.started - 1).is_err());
    assert!(original.check(&auth, current.grant.expires).is_err());
    // Replacing the ACTUAL stored session invalidates every retained lease,
    // even when the genuine credential/grant fields themselves are unchanged.
    owner.sessions.get_mut(&world.garden).unwrap().authority = session_authority::Owner::default();
    assert!(original.check(&auth, NOW).is_err());
    let current = owner.sessions.get(&world.garden).unwrap();
    let replacement =
        current
            .authority
            .role_lease(auth.clone(), current.grant.clone(), current.started);
    assert!(replacement.check(&auth, NOW).is_ok());
    owner.logout(&world.garden);
    assert!(replacement.check(&auth, NOW).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_genuine_key_of_the_same_member_cannot_replace_retained_role_session() {
    let world = world().await;
    let member = client(&world.source, SOURCE, Some(&world.member.session));
    let addition: AddedPasskey = serde_json::from_value(
        member
            .call("passkey_add", json!({"step":"begin"}))
            .await
            .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Challenge {
        ceremony, options, ..
    } = addition
    else {
        panic!("challenge")
    };
    let mut second = SoftToken::new(true).unwrap().0;
    let mut options: ckyh::CreationChallengeResponse = serde_json::from_value(options).unwrap();
    options
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let response: ckyh::RegisterPublicKeyCredential = second
        .perform_register(
            ckyh::Url::parse(&format!("https://{SOURCE}")).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap()
        .into();
    let credential = response.raw_id.as_ref().to_vec();
    member
        .call(
            "passkey_add",
            json!({"step":"finish","ceremony":ceremony,"credential":response}),
        )
        .await
        .unwrap();
    let second_session = login(
        &world.source,
        SOURCE,
        &mut second,
        &world.member.user,
        &credential,
    )
    .await;
    let owner = world.source.door.community_backend().unwrap().lock().await;
    let current = owner.sessions.get(&world.garden).unwrap();
    let retained = current.authority.role_lease(
        current.authentication.clone(),
        current.grant.clone(),
        current.started,
    );
    let other = &owner.sessions.get(&second_session).unwrap().authentication;
    assert_eq!(other.member(), current.authentication.member());
    assert_ne!(
        other.credential_id(),
        current.authentication.credential_id()
    );
    assert!(retained.check(other, NOW).is_err());
    assert!(retained.check(&current.authentication, NOW).is_ok());
    let foreign = foreign::authentication(&owner).await;
    assert_ne!(foreign.member(), current.authentication.member());
    assert!(retained.check(&foreign, NOW).is_err());
}

struct RetainedEntry {
    actual: Arc<dyn cmbr::RoleSession>,
    entries: std::sync::atomic::AtomicUsize,
    completing: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}
impl cmbr::RoleSession for RetainedEntry {
    fn valid_until(&self) -> u64 {
        self.actual.valid_until()
    }
    fn check(&self, authentication: &ckyh::Authentication, observed: u64) -> cmbr::Result<()> {
        self.actual.check(authentication, observed)?;
        // These are the explicit host-entry and detached completing-entry
        // checks, not a guessed count of cryptographic or database calls. The
        // observer always forwards genuine host authority, never approves it.
        if self
            .entries
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            == 1
        {
            if let Some(sender) = self.completing.lock().unwrap().take() {
                let _ = sender.send(());
            }
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_cancellation_then_real_logout_refuses_the_detached_original_role_writer() {
    let world = world().await;
    let mut owner = world.source.door.community_backend().unwrap().lock().await;
    assert!(owner.accounts.is_none());
    let current = owner.sessions.get(&world.garden).unwrap();
    let auth = current.authentication.clone();
    let grant = current.grant.clone();
    let actual = current
        .authority
        .role_lease(auth.clone(), grant.clone(), current.started);
    let (entered, received) = tokio::sync::oneshot::channel();
    let retained = Arc::new(RetainedEntry {
        actual,
        entries: Default::default(),
        completing: std::sync::Mutex::new(Some(entered)),
    });
    let membership = owner.facade.membership().clone();
    let lease = membership.role(&auth).await.unwrap();
    let subject = lease.member().to_owned();
    drop(lease);
    let held = owner.db.community("alpha").unwrap().tx().await.unwrap();
    let mut request = Box::pin(membership.set_member_role_checked(
        &auth,
        &subject,
        cmbr::Role::Admin,
        NOW,
        grant.expires,
        retained.clone(),
    ));
    tokio::select! {
        result = &mut request => panic!("unexpected early completion: {result:?}"),
        result = received => result.unwrap(),
    }
    drop(request);
    assert!(
        Arc::strong_count(&retained) > 1,
        "the actual detached owner retains this same capability"
    );
    owner.logout(&world.garden);
    held.rollback().await.unwrap();
    // The detached operation owns the original member mutex. This fresh real
    // role read waits for its completion, then observes the unchanged record.
    let lease = tokio::time::timeout(std::time::Duration::from_secs(5), membership.role(&auth))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.role(), cmbr::Role::Root);
    assert_eq!(Arc::strong_count(&retained), 1);
    assert!(retained.check(&auth, NOW).is_err());
}
