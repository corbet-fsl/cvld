//! The birth grant (C1, C2) through real passkey ceremonies: the registration's own session,
//! a wallet login, T_birth, one live passkey only, and sessions that never carry it.
use super::*;
use crate::test_support::TestClock;
use std::sync::atomic::AtomicU64;

fn wallet_keys(db: &crlt::Db) -> Passkeys<LibsqlStore> {
    Passkeys::new(
        LibsqlStore::new(db, "wallet", tokio::runtime::Handle::current()).unwrap(),
        "wallet",
        "auth.example.test",
        &[ckyh::Url::parse(ORIGIN).unwrap()],
    )
    .unwrap()
}

/// Sessions live for the longest lifetime (one hour), longer than the birth window.
fn wallet_auth(db: &crlt::Db) -> Auth {
    Auth::new(wallet_keys(db), Role::Member, None, None, 8, 3600).unwrap()
}

/// Register through the wallet path; the returned session is the birth session.
async fn born(auth: &mut Auth, device: &mut Resident) -> Session {
    let begin = auth.register_begin(start(None), NOW).await.unwrap();
    let finish = registration(device, begin).await;
    let clock = TestClock(AtomicU64::new(NOW));
    let registered = auth
        .register_finish_wallet_live(finish, NOW, &clock, None, true)
        .await
        .unwrap();
    let session = registered.session.expect("the wallet registration mints a session");
    assert_eq!(session.user, registered.user);
    session
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_registration_session_holds_the_birth_grant_until_t_birth() {
    let (_directory, db) = database().await;
    let mut auth = wallet_auth(&db);
    let window = crate::auth::birth::BIRTH_UV_WINDOW;
    assert_eq!(window, 30 * 60);
    let mut device = Resident::default();
    let session = born(&mut auth, &mut device).await;
    let grant = auth.birth_grant(&session.token, NOW).await.unwrap();
    assert_eq!(grant.uv_at, Some(NOW));
    assert_eq!(grant.user.to_string(), session.user);
    // Each use rechecks: at T_birth still granted, one second later refused for good.
    auth.birth_grant(&session.token, NOW + window).await.unwrap();
    assert!(matches!(
        auth.birth_grant(&session.token, NOW + window + 1).await,
        Err(Error::Forbidden)
    ));
    // The session itself is untouched by the refusal.
    auth.authenticate(&session.token, NOW + window + 1).await.unwrap();
    // A restart's wallet login is a fresh user verification and opens a new window.
    let finish = login(&mut auth, &mut device).await;
    let login = auth.login_finish(finish, NOW + 100).await.unwrap();
    assert_eq!(
        auth.birth_grant(&login.token, NOW + window + 1)
            .await
            .unwrap()
            .uv_at,
        Some(NOW + 100)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_passkey_or_a_session_without_birth_origin_is_refused() {
    let (_directory, db) = database().await;
    let mut auth = wallet_auth(&db);
    let mut device = Resident::default();
    let session = born(&mut auth, &mut device).await;
    let finish = login(&mut auth, &mut device).await;
    let login = auth.login_finish(finish, NOW).await.unwrap();
    // A session that was not minted by a registration, a login or a fork of those.
    auth.sessions.get_mut(&login.token).unwrap().grant.uv_at = None;
    assert!(matches!(
        auth.birth_grant(&login.token, NOW).await,
        Err(Error::Forbidden)
    ));
    // A device-key origin never carries it either.
    {
        let state = auth.sessions.get_mut(&login.token).unwrap();
        state.grant.uv_at = Some(NOW);
        state.grant.origin = ckyh::Origin::DeviceKey;
    }
    assert!(matches!(
        auth.birth_grant(&login.token, NOW).await,
        Err(Error::Forbidden)
    ));
    auth.birth_grant(&session.token, NOW).await.unwrap();
    // A second live passkey ends the birth grant of every session of the account, including
    // the registration's own session whose credential is still live.
    let user: Uuid = session.user.parse().unwrap();
    let passkeys = auth.passkeys.clone();
    let (challenge, pending) =
        tokio::task::spawn_blocking(move || passkeys.start_registration(user).unwrap())
            .await
            .unwrap();
    let mut second = Resident::default();
    let mut response = second
        .ceremony(serde_json::to_value(challenge).unwrap(), true, ORIGIN)
        .await;
    strip_prf(&mut response);
    let response: ckyh::RegisterPublicKeyCredential = serde_json::from_value(response).unwrap();
    let passkeys = auth.passkeys.clone();
    tokio::task::spawn_blocking(move || {
        passkeys
            .finish_registration(pending, &response, creation_month(NOW).unwrap())
            .unwrap()
    })
    .await
    .unwrap();
    assert!(matches!(
        auth.birth_grant(&session.token, NOW).await,
        Err(Error::Forbidden)
    ));
    auth.authenticate(&session.token, NOW).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_wallet_member_auth_mints_and_grants() {
    let (_directory, db) = database().await;
    // A community Auth: registration mints no session and no session holds the grant.
    let mut community = auth(&db, None, 8);
    let mut device = Resident::default();
    let begin = community.register_begin(start(None), NOW).await.unwrap();
    let finish = registration(&mut device, begin).await;
    let clock = TestClock(AtomicU64::new(NOW));
    community
        .register_finish_live(finish, NOW, &clock)
        .await
        .unwrap();
    let finish = login(&mut community, &mut device).await;
    let session = community.login_finish(finish, NOW).await.unwrap();
    assert!(matches!(
        community.birth_grant(&session.token, NOW).await,
        Err(Error::Forbidden)
    ));
    // A full session table refuses the wallet registration before its ceremony is consumed.
    let (_directory, db) = database().await;
    let mut wallet = Auth::new(wallet_keys(&db), Role::Member, None, None, 1, 600).unwrap();
    let mut device = Resident::default();
    let first = born(&mut wallet, &mut device).await;
    let mut other = Resident::default();
    let begin = wallet.register_begin(start(None), NOW).await.unwrap();
    let ceremony = begin.ceremony.clone();
    let finish = registration(&mut other, begin).await;
    assert!(matches!(
        wallet
            .register_finish_wallet_live(finish, NOW, &clock, None, true)
            .await,
        Err(Error::Throttled)
    ));
    assert!(wallet.registrations.contains_key(&ceremony));
    wallet.birth_grant(&first.token, NOW).await.unwrap();
}
