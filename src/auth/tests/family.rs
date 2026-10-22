//! C6 session families through real passkey ceremonies: limits, deadlines, revocation.
use super::*;

async fn member(db: &crlt::Db, capacity: usize) -> (Auth, Session) {
    let mut member = auth(db, None, capacity);
    let mut device = Resident::default();
    let begin = member.register_begin(start(None), NOW).await.unwrap();
    let finish = registration(&mut device, begin).await;
    member.register_finish(finish, NOW).await.unwrap();
    let finish = login(&mut member, &mut device).await;
    let session = member.login_finish(finish, NOW).await.unwrap();
    (member, session)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fork_has_the_parents_grant_and_deadline_under_a_fresh_session_id() {
    let (_directory, db) = database().await;
    let (mut auth, parent) = member(&db, 8).await;
    let sibling = auth.fork(&parent.token, NOW + 10).await.unwrap();
    assert_ne!(sibling.token, parent.token);
    assert_eq!(sibling.user, parent.user);
    assert_eq!(sibling.role, parent.role);
    assert_eq!(sibling.expires, parent.expires);
    let first = auth.authenticate(&parent.token, NOW + 10).await.unwrap();
    let second = auth.authenticate(&sibling.token, NOW + 10).await.unwrap();
    assert_eq!(first.user, second.user);
    assert_eq!(first.credential, second.credential);
    assert_eq!(first.origin, second.origin);
    assert_eq!(first.expires, second.expires);
    assert_ne!(first.session_id, second.session_id);
    let (parent_state, sibling_state) = (
        &auth.sessions[&parent.token],
        &auth.sessions[&sibling.token],
    );
    assert!(Arc::ptr_eq(
        &parent_state.authentication,
        &sibling_state.authentication
    ));
    assert_eq!(parent_state.family, sibling_state.family);
    assert_eq!(parent_state.family, first.session_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fork_never_renews_and_a_fork_of_a_fork_keeps_the_first_deadline() {
    let (_directory, db) = database().await;
    let (mut auth, parent) = member(&db, 8).await;
    let sibling = auth.fork(&parent.token, NOW + 300).await.unwrap();
    let grandchild = auth.fork(&sibling.token, NOW + 599).await.unwrap();
    assert_eq!(grandchild.expires, parent.expires);
    assert!(grandchild.expires <= sibling.expires && sibling.expires <= parent.expires);
    // At the shared deadline the whole family has ended; nothing forks past it.
    for token in [&parent.token, &sibling.token, &grandchild.token] {
        assert!(matches!(
            auth.fork(token, parent.expires).await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            auth.authenticate(token, parent.expires).await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(auth.sessions.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_family_limit_counts_live_members_and_is_checked_when_set() {
    let (_directory, db) = database().await;
    let (mut auth, parent) = member(&db, 16).await;
    for limit in [0, MAX_FAMILY_LIMIT + 1] {
        assert!(matches!(auth.set_family_limit(limit), Err(Error::Invalid)));
    }
    assert_eq!(auth.family_limit, DEFAULT_FAMILY_LIMIT);
    let second = auth.fork(&parent.token, NOW).await.unwrap();
    let third = auth.fork(&second.token, NOW).await.unwrap();
    // Default 3: the login and two forks.
    for token in [&parent.token, &second.token, &third.token] {
        assert!(matches!(auth.fork(token, NOW).await, Err(Error::Refused)));
    }
    auth.set_family_limit(4).unwrap();
    auth.fork(&third.token, NOW).await.unwrap();
    assert!(matches!(
        auth.fork(&parent.token, NOW).await,
        Err(Error::Refused)
    ));
    let (_other_directory, other_db) = database().await;
    let (mut single, only) = member(&other_db, 16).await;
    single.set_family_limit(1).unwrap();
    assert!(matches!(
        single.fork(&only.token, NOW).await,
        Err(Error::Refused)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forks_share_the_session_capacity() {
    let (_directory, db) = database().await;
    let (mut auth, parent) = member(&db, 2).await;
    auth.fork(&parent.token, NOW).await.unwrap();
    let (_other_directory, other_db) = database().await;
    let (mut full, only) = member(&other_db, 1).await;
    assert!(matches!(
        full.fork(&only.token, NOW).await,
        Err(Error::Throttled)
    ));
    assert!(matches!(
        auth.fork(&parent.token, NOW).await,
        Err(Error::Throttled)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_of_any_member_ends_the_whole_family_and_no_other() {
    let (_directory, db) = database().await;
    let mut auth = auth(&db, None, 8);
    let mut device = Resident::default();
    let begin = auth.register_begin(start(None), NOW).await.unwrap();
    let finish = registration(&mut device, begin).await;
    auth.register_finish(finish, NOW).await.unwrap();
    let finish = login(&mut auth, &mut device).await;
    let parent = auth.login_finish(finish, NOW).await.unwrap();
    let finish = login(&mut auth, &mut device).await;
    let other = auth.login_finish(finish, NOW).await.unwrap();
    let sibling = auth.fork(&parent.token, NOW).await.unwrap();
    let grandchild = auth.fork(&sibling.token, NOW).await.unwrap();
    auth.logout(&grandchild.token);
    for token in [&parent.token, &sibling.token, &grandchild.token] {
        assert!(matches!(
            auth.authenticate(token, NOW).await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            auth.fork(token, NOW).await,
            Err(Error::Unauthorized)
        ));
    }
    // Another login of the same account is another family.
    auth.authenticate(&other.token, NOW).await.unwrap();
    assert_eq!(auth.sessions.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_revocation_ends_every_member() {
    let (_directory, db) = database().await;
    let (mut auth, parent) = member(&db, 8).await;
    let sibling = auth.fork(&parent.token, NOW).await.unwrap();
    let grant = auth.authenticate(&sibling.token, NOW).await.unwrap();
    let passkeys = auth.passkeys.clone();
    tokio::task::spawn_blocking(move || passkeys.revoke(grant.user, &grant.credential))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        auth.fork(&sibling.token, NOW).await,
        Err(Error::Unauthorized)
    ));
    // The refused member's check ended its family, the parent included.
    assert!(auth.sessions.is_empty());
    assert!(matches!(
        auth.authenticate(&parent.token, NOW).await,
        Err(Error::Unauthorized)
    ));
}
