//! Real UV resident ceremonies exercise equal-standing account management.
use super::*;

fn account_auth(db: &crlt::Db, role: Role, operator: Option<Uuid>, capacity: usize) -> Auth {
    Auth::new(
        keys(db),
        role,
        operator,
        operator.map(|_| zeroize::Zeroizing::new(BOOTSTRAP.into())),
        capacity,
        600,
    )
    .unwrap()
}
async fn enrol_account(auth: &mut Auth, device: &mut Resident) -> (User, Session) {
    let begin = auth
        .register_begin(start(auth.operator.map(|_| BOOTSTRAP)), NOW)
        .await
        .unwrap();
    let request = registration(device, begin).await;
    let user = auth.register_finish(request, NOW).await.unwrap();
    let finish = login(auth, device).await;
    let session = auth.login_finish(finish, NOW).await.unwrap();
    (user, session)
}
async fn addition(auth: &mut Auth, session: &str, device: &mut Resident) -> (String, AddPasskey) {
    let AddedPasskey::Challenge {
        ceremony,
        user,
        options,
    } = auth
        .add_passkey(session, AddPasskey::Begin, NOW)
        .await
        .unwrap()
    else {
        panic!("expected an independently authenticated registration challenge");
    };
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["residentKey"],
        "required"
    );
    let mut response = device.ceremony(options, true, ORIGIN).await;
    strip_prf(&mut response);
    (
        user,
        AddPasskey::Finish {
            ceremony,
            credential: serde_json::from_value(response).unwrap(),
        },
    )
}
fn copy_request(request: &AddPasskey) -> AddPasskey {
    serde_json::from_value(serde_json::to_value(request).unwrap()).unwrap()
}
fn listed(list: &PasskeyList, credential: &[u8]) -> (bool, bool) {
    let key = list
        .passkeys
        .iter()
        .find(|key| key.credential == credential)
        .unwrap();
    assert!(key.created_year > 2000);
    assert!((1..=12).contains(&key.created_month));
    (key.revoked, key.current)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_account_roles_add_list_and_revoke_equal_keys_without_changing_identity() {
    for role in [Role::Member, Role::Root, Role::Admin] {
        let (directory, db) = database().await;
        let operator = (role != Role::Member).then(Uuid::new_v4);
        let mut auth = account_auth(&db, role, operator, 4);
        let mut original = Resident::default();
        let (user, original_session) = enrol_account(&mut auth, &mut original).await;
        assert_eq!(original_session.role, role);
        let original_id = auth
            .authenticate(&original_session.token, NOW)
            .await
            .unwrap()
            .credential;
        let initial = auth
            .list_passkeys(&original_session.token, NOW)
            .await
            .unwrap();
        assert_eq!(initial.passkeys.len(), 1);
        assert_eq!(listed(&initial, original_id.as_ref()), (false, true));
        let mut added = Resident::default();
        let (expected_user, request) =
            addition(&mut auth, &original_session.token, &mut added).await;
        assert_eq!(expected_user, user.user);
        let response = auth
            .add_passkey(&original_session.token, copy_request(&request), NOW)
            .await
            .unwrap();
        let AddedPasskey::Registered {
            user: registered_user,
            credential,
        } = response
        else {
            panic!("registered key")
        };
        assert_eq!(registered_user, user.user);
        assert!(matches!(
            auth.add_passkey(&original_session.token, request, NOW)
                .await,
            Err(Error::Unauthorized)
        ));
        let finish = login(&mut auth, &mut added).await;
        let added_session = auth.login_finish(finish, NOW).await.unwrap();
        assert_eq!(added_session.user, user.user);
        assert_eq!(added_session.role, role);
        let view = auth.list_passkeys(&added_session.token, NOW).await.unwrap();
        assert_eq!(view.passkeys.len(), 2);
        assert_eq!(listed(&view, original_id.as_ref()), (false, false));
        assert_eq!(listed(&view, &credential), (false, true));
        let (_, pending) =
            addition(&mut auth, &original_session.token, &mut Resident::default()).await;
        auth.revoke_passkey(&added_session.token, original_id.clone(), NOW)
            .await
            .unwrap();
        assert!(matches!(
            auth.authenticate(&original_session.token, NOW).await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            auth.add_passkey(&added_session.token, pending, NOW).await,
            Err(Error::Unauthorized)
        ));
        let view = auth.list_passkeys(&added_session.token, NOW).await.unwrap();
        assert_eq!(listed(&view, original_id.as_ref()), (true, false));
        assert_eq!(listed(&view, &credential), (false, true));
        auth.revoke_passkey(&added_session.token, credential.into(), NOW)
            .await
            .unwrap();
        assert!(matches!(
            auth.list_passkeys(&added_session.token, NOW).await,
            Err(Error::Unauthorized)
        ));
        let reopened_db = crlt::Db::open(crlt::Config::new(
            format!("file://{}", directory.path().join("auth.db").display()),
            "",
        ))
        .await
        .unwrap();
        reopened_db
            .migrate(&[crlt::Migration::new(1, "passkeys", ckyh::LIBSQL_SCHEMA)])
            .await
            .unwrap();
        let mut reopened = account_auth(&reopened_db, role, operator, 4);
        let keys = reopened.passkeys.clone();
        let account = Uuid::parse_str(&user.user).unwrap();
        let records = tokio::task::spawn_blocking(move || keys.list(account))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(ckyh::StoredPasskey::is_revoked));
        assert!(matches!(
            reopened.authenticate(&added_session.token, NOW).await,
            Err(Error::Unauthorized)
        ));
        let finish = login(&mut reopened, &mut added).await;
        assert!(matches!(
            reopened.login_finish(finish, NOW).await,
            Err(Error::Unauthorized)
        ));
        if operator.is_some() {
            assert!(matches!(
                reopened.register_begin(start(Some(BOOTSTRAP)), NOW).await,
                Err(Error::Refused)
            ));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_session_account_or_auth_host_cannot_finish_or_revoke_the_owner_keys() {
    let (_directory, db) = database().await;
    let mut auth = account_auth(&db, Role::Member, None, 4);
    let mut owner_device = Resident::default();
    let (owner, owner_session) = enrol_account(&mut auth, &mut owner_device).await;
    let finish = login(&mut auth, &mut owner_device).await;
    let alternate = auth.login_finish(finish, NOW).await.unwrap();
    let (_, stranger) = enrol_account(&mut auth, &mut Resident::default()).await;
    let stranger_key = auth
        .authenticate(&stranger.token, NOW)
        .await
        .unwrap()
        .credential;
    let (_, request) = addition(&mut auth, &owner_session.token, &mut Resident::default()).await;
    for token in [&alternate.token, &stranger.token, "foreign-token"] {
        assert!(matches!(
            auth.add_passkey(token, copy_request(&request), NOW).await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(matches!(
        auth.revoke_passkey(&owner_session.token, stranger_key, NOW)
            .await,
        Err(Error::Refused)
    ));
    let mut other_host = account_auth(&db, Role::Root, Some(Uuid::new_v4()), 4);
    assert!(matches!(
        other_host
            .add_passkey(&owner_session.token, copy_request(&request), NOW)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        other_host.list_passkeys(&owner_session.token, NOW).await,
        Err(Error::Unauthorized)
    ));
    let AddedPasskey::Registered { user, .. } = auth
        .add_passkey(&owner_session.token, request, NOW)
        .await
        .unwrap()
    else {
        panic!("owner completed")
    };
    assert_eq!(user, owner.user);
    assert_eq!(
        auth.list_passkeys(&stranger.token, NOW)
            .await
            .unwrap()
            .passkeys
            .len(),
        1
    );
    assert_eq!(
        auth.list_passkeys(&owner_session.token, NOW)
            .await
            .unwrap()
            .passkeys
            .len(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_logged_out_or_externally_revoked_authorizers_cannot_add_keys() {
    for cause in ["ceremony-expiry", "session-expiry", "logout", "revocation"] {
        let (_directory, db) = database().await;
        let mut auth = account_auth(&db, Role::Member, None, 4);
        let mut device = Resident::default();
        let (_, session) = enrol_account(&mut auth, &mut device).await;
        let (_, request) = addition(&mut auth, &session.token, &mut Resident::default()).await;
        let grant = auth.authenticate(&session.token, NOW).await.unwrap();
        let now = match cause {
            "ceremony-expiry" => NOW + 300,
            "session-expiry" => NOW + 600,
            "logout" => {
                auth.logout(&session.token);
                NOW
            }
            "revocation" => {
                let keys = auth.passkeys.clone();
                let id = grant.credential.clone();
                tokio::task::spawn_blocking(move || keys.revoke(grant.user, &id))
                    .await
                    .unwrap()
                    .unwrap();
                NOW
            }
            _ => unreachable!(),
        };
        assert!(
            matches!(
                auth.add_passkey(&session.token, request, now).await,
                Err(Error::Unauthorized)
            ),
            "{cause}"
        );
        let keys = auth.passkeys.clone();
        let records = tokio::task::spawn_blocking(move || keys.list(grant.user))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(records.len(), 1, "{cause}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replacing_one_sessions_addition_preserves_the_other_and_exact_expiry_clears_both() {
    let (_directory, db) = database().await;
    let mut auth = account_auth(&db, Role::Member, None, 2);
    let mut device = Resident::default();
    let (_, first) = enrol_account(&mut auth, &mut device).await;
    let finish = login(&mut auth, &mut device).await;
    let second = auth.login_finish(finish, NOW).await.unwrap();
    let (_, stale) = addition(&mut auth, &first.token, &mut Resident::default()).await;
    let (_, second_pending) = addition(&mut auth, &second.token, &mut Resident::default()).await;
    let (_, current) = addition(&mut auth, &first.token, &mut Resident::default()).await;
    assert_eq!(auth.sessions.len(), 2);
    assert_eq!(auth.additions.len(), 2);
    assert!(matches!(
        auth.add_passkey(&first.token, stale, NOW).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(auth.additions.len(), 2);
    // The other session's original pending ceremony still completes, while the
    // first session retains its replacement ceremony for the expiry check.
    assert!(matches!(
        auth.add_passkey(&second.token, second_pending, NOW)
            .await
            .unwrap(),
        AddedPasskey::Registered { .. }
    ));
    assert_eq!(auth.additions.len(), 1);
    let (_, second_pending) = addition(&mut auth, &second.token, &mut Resident::default()).await;
    assert_eq!(auth.additions.len(), 2);
    assert!(matches!(
        auth.add_passkey(&first.token, current, NOW + 300).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(auth.additions.len(), 0);
    assert!(matches!(
        auth.add_passkey(&second.token, second_pending, NOW + 300)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        auth.add_passkey(&second.token, AddPasskey::Begin, NOW + 300)
            .await
            .unwrap(),
        AddedPasskey::Challenge { .. }
    ));
}
