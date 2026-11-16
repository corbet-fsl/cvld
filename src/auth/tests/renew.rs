//! A13: wallet session renewal by the wallet device key K (secure convenience, M1-M4).
//! Written red first; the API named here is the one the implementation provides:
//! `Auth::wallet_renew_begin`, `Auth::wallet_renew`, the durable anchor written at login (M2)
//! and removed by revocation, and the binding check at renewal (M4, `bound`).
use super::*;
use crate::device_session::{wallet_login_message, wallet_message};
use ed25519_dalek::{Signer, SigningKey};

const HOST: &str = "wallet.example.test";

/// A database with the passkeys and the durable anchor table (A13 M1).
async fn wallet_database() -> (tempfile::TempDir, crlt::Db) {
    let directory = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", directory.path().join("wallet.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&[
        crlt::Migration::new(1, "passkeys", ckyh::LIBSQL_SCHEMA),
        crlt::Migration::new(
            2,
            "wallet-session-anchors",
            crate::wallet_session_anchors::SCHEMA,
        ),
    ])
    .await
    .unwrap();
    (directory, db)
}

/// A wallet host's Auth: its passkey community is "wallet" and its anchors are durable, as in
/// production. Each call is a fresh process's Auth over the same database.
fn wallet_auth(db: &crlt::Db) -> Auth {
    let passkeys = Passkeys::new(
        LibsqlStore::new(db, "wallet", tokio::runtime::Handle::current()).unwrap(),
        "wallet",
        "auth.example.test",
        &[ckyh::Url::parse(ORIGIN).unwrap()],
    )
    .unwrap();
    Auth::new(passkeys, Role::Member, None, None, 16, 600)
        .unwrap()
        .with_wallet_anchors(db.community("global").unwrap())
}

/// A registered member, logged in once by passkey (no K proof).
async fn member(db: &crlt::Db) -> (Auth, Session, [u8; 32]) {
    let (auth, _, session, family) = member_device(db).await;
    (auth, session, family)
}

async fn member_device(db: &crlt::Db) -> (Auth, Resident, Session, [u8; 32]) {
    let mut member = wallet_auth(db);
    let mut device = Resident::default();
    let begin = member.register_begin(start(None), NOW).await.unwrap();
    let finish = registration(&mut device, begin).await;
    member.register_finish(finish, NOW).await.unwrap();
    let finish = login(&mut member, &mut device).await;
    let session = member.login_finish(finish, NOW).await.unwrap();
    let family = member.sessions[&session.token].family;
    (member, device, session, family)
}

fn renewal(
    key: &SigningKey,
    session: &Session,
    family: [u8; 32],
    challenge: &DeviceSessionChallenge,
) -> WalletSessionRenew {
    let account = *Uuid::parse_str(&session.user).unwrap().as_bytes();
    let message = wallet_message(HOST, &account, &family, &challenge.nonce, challenge.issued);
    WalletSessionRenew {
        account: session.user.clone(),
        family,
        device_key: key.verifying_key().to_bytes(),
        nonce: challenge.nonce,
        signature: key.sign(&message).to_bytes().to_vec(),
    }
}

/// M4 stand-in for the cgbl binding: K is bound to the anchored credential.
fn bound_to(key: &SigningKey) -> impl AsyncFn(Uuid, ckyh::CredentialID, [u8; 32]) -> Result<bool> {
    let expected = key.verifying_key().to_bytes();
    async move |_, _, device| Ok(device == expected)
}

/// Renew `family` by `key` at `at` with a fresh nonce.
async fn renew(
    auth: &mut Auth,
    key: &SigningKey,
    session: &Session,
    family: [u8; 32],
    at: u64,
) -> Result<Session> {
    let challenge = auth.wallet_renew_begin(at).await.unwrap();
    auth.wallet_renew(
        HOST,
        renewal(key, session, family, &challenge),
        at,
        bound_to(key),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anchored_device_key_renews_the_wallet_session_without_a_prompt() {
    let (_directory, db) = wallet_database().await;
    let (mut auth, session, family) = member(&db).await;
    let key = SigningKey::from_bytes(&[7; 32]);
    auth.anchor_wallet_device(&session.token, key.verifying_key().to_bytes(), NOW)
        .await
        .unwrap();
    let at = session.expires - 60;
    let challenge = auth.wallet_renew_begin(at).await.unwrap();
    let renewed = auth
        .wallet_renew(
            HOST,
            renewal(&key, &session, family, &challenge),
            at,
            bound_to(&key),
        )
        .await
        .unwrap();
    assert_ne!(renewed.token, session.token);
    assert_eq!(renewed.user, session.user);
    assert_eq!(renewed.expires, at + 600);
    let grant = auth.authenticate(&renewed.token, at).await.unwrap();
    let first = auth.authenticate(&session.token, at).await.unwrap();
    // Same passkey credential C, a new member of the same family, no birth grant (C2).
    assert_eq!(grant.credential, first.credential);
    assert_eq!(grant.origin, ckyh::Origin::DeviceKey);
    assert_eq!(grant.uv_at, None);
    assert_eq!(auth.sessions[&renewed.token].family, family);
    // The old generation keeps its own deadline; the renewed one outlives it (no lifetime cap on
    // the chain: only revocation ends it).
    let later = session.expires + 30;
    assert!(auth.authenticate(&renewed.token, later).await.is_ok());
    let challenge = auth.wallet_renew_begin(renewed.expires - 60).await.unwrap();
    let again = auth
        .wallet_renew(
            HOST,
            renewal(&key, &session, family, &challenge),
            renewed.expires - 60,
            bound_to(&key),
        )
        .await
        .unwrap();
    assert!(again.expires > renewed.expires);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_device_key_is_refused() {
    let (_directory, db) = wallet_database().await;
    let (mut auth, session, family) = member(&db).await;
    let key = SigningKey::from_bytes(&[7; 32]);
    let device = key.verifying_key().to_bytes();
    auth.anchor_wallet_device(&session.token, device, NOW)
        .await
        .unwrap();
    let user = Uuid::parse_str(&session.user).unwrap();
    auth.revoke_wallet_device(user, device).await.unwrap();
    let at = session.expires - 60;
    let challenge = auth.wallet_renew_begin(at).await.unwrap();
    assert_eq!(
        auth.wallet_renew(
            HOST,
            renewal(&key, &session, family, &challenge),
            at,
            bound_to(&key)
        )
        .await
        .err(),
        Some(Error::Unauthorized)
    );
    // Revocation also ends the families the key renewed.
    assert!(auth.authenticate(&session.token, NOW + 1).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_key_never_anchored_is_refused() {
    let (_directory, db) = wallet_database().await;
    let (mut auth, session, family) = member(&db).await;
    let anchored = SigningKey::from_bytes(&[7; 32]);
    auth.anchor_wallet_device(&session.token, anchored.verifying_key().to_bytes(), NOW)
        .await
        .unwrap();
    let stranger = SigningKey::from_bytes(&[9; 32]);
    let at = session.expires - 60;
    let challenge = auth.wallet_renew_begin(at).await.unwrap();
    // Even when the binding check would pass, a key with no anchor row renews nothing.
    assert_eq!(
        auth.wallet_renew(
            HOST,
            renewal(&stranger, &session, family, &challenge),
            at,
            async |_, _, _| Ok(true),
        )
        .await
        .err(),
        Some(Error::Unauthorized)
    );
    // The anchored key with a family it was never anchored in is refused as well.
    let challenge = auth.wallet_renew_begin(at).await.unwrap();
    assert_eq!(
        auth.wallet_renew(
            HOST,
            renewal(&anchored, &session, [0; 32], &challenge),
            at,
            bound_to(&anchored),
        )
        .await
        .err(),
        Some(Error::Unauthorized)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renewal_keeps_the_binding_and_refuses_an_unbound_key() {
    let (_directory, db) = wallet_database().await;
    let (mut auth, session, family) = member(&db).await;
    let key = SigningKey::from_bytes(&[7; 32]);
    let device = key.verifying_key().to_bytes();
    auth.anchor_wallet_device(&session.token, device, NOW)
        .await
        .unwrap();
    let at = session.expires - 60;
    // M4: K rebound away from C (cgbl reports no binding) refuses the renewal.
    let challenge = auth.wallet_renew_begin(at).await.unwrap();
    assert_eq!(
        auth.wallet_renew(
            HOST,
            renewal(&key, &session, family, &challenge),
            at,
            async |_, _, _| Ok(false),
        )
        .await
        .err(),
        Some(Error::Unauthorized)
    );
    // A renewal that succeeds is checked against exactly the anchored (member, C, K).
    let first = auth.authenticate(&session.token, at).await.unwrap();
    let seen = std::sync::Mutex::new(None);
    let challenge = auth.wallet_renew_begin(at).await.unwrap();
    let renewed = auth
        .wallet_renew(
            HOST,
            renewal(&key, &session, family, &challenge),
            at,
            async |user, credential: ckyh::CredentialID, k| {
                *seen.lock().unwrap() = Some((user, credential, k));
                Ok(true)
            },
        )
        .await
        .unwrap();
    assert_eq!(
        seen.into_inner().unwrap(),
        Some((first.user, first.credential.clone(), device))
    );
    let grant = auth.authenticate(&renewed.token, at).await.unwrap();
    assert_eq!(grant.credential, first.credential);
    assert_eq!(
        auth.sessions[&renewed.token].authentication.device_key(),
        Some(device)
    );
    // A replayed nonce is spent.
    assert_eq!(
        auth.wallet_renew(
            HOST,
            renewal(&key, &session, family, &challenge),
            at,
            bound_to(&key),
        )
        .await
        .err(),
        Some(Error::Unauthorized)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renewed_session_needs_the_passkey_for_passkey_only_wallet_actions() {
    let (_directory, db) = wallet_database().await;
    let (mut auth, session, family) = member(&db).await;
    let key = SigningKey::from_bytes(&[7; 32]);
    auth.anchor_wallet_device(&session.token, key.verifying_key().to_bytes(), NOW)
        .await
        .unwrap();
    let at = session.expires - 60;
    let clock = crate::auth::enrollment::FixedClock(at);
    // The passkey session reaches the passkey-only paths (devices, certificate).
    let grant = auth.authenticate(&session.token, at).await.unwrap();
    let mut wallet = auth
        .wallet_session(&session.token, &grant, at, &clock)
        .await
        .unwrap();
    wallet
        .check(&mut auth, &session.token, at, &clock)
        .await
        .unwrap();
    assert!(wallet.passkey_member().is_ok());
    // The K-renewed session is a wallet session, but those paths answer NeedsPasskey (step-up).
    let challenge = auth.wallet_renew_begin(at).await.unwrap();
    let renewed = auth
        .wallet_renew(
            HOST,
            renewal(&key, &session, family, &challenge),
            at,
            bound_to(&key),
        )
        .await
        .unwrap();
    let grant = auth.authenticate(&renewed.token, at).await.unwrap();
    let mut wallet = auth
        .wallet_session(&renewed.token, &grant, at, &clock)
        .await
        .unwrap();
    wallet
        .check(&mut auth, &renewed.token, at, &clock)
        .await
        .unwrap();
    assert!(wallet.member().is_ok());
    assert_eq!(wallet.passkey_member().err(), Some(Error::NeedsPasskey));
}

/// M1: the anchor row survives the process, so a restarted host renews without a prompt; a
/// revocation in another process ends a renewed session at its next request (read-through);
/// a logout (explicit lock) deletes the row for every process.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_keeps_the_chain_and_a_logout_ends_it_durably() {
    let (_directory, db) = wallet_database().await;
    let (mut first, session, family) = member(&db).await;
    let key = SigningKey::from_bytes(&[9; 32]);
    first
        .anchor_wallet_device(&session.token, key.verifying_key().to_bytes(), NOW)
        .await
        .unwrap();
    drop(first);
    // The host restarts: the new Auth has no sessions, only the durable anchors.
    let mut second = wallet_auth(&db);
    let at = NOW + 360;
    let renewed = renew(&mut second, &key, &session, family, at)
        .await
        .unwrap();
    assert_eq!(renewed.user, session.user);
    assert_eq!(renewed.family, Some(family));
    assert!(second.authenticate(&renewed.token, at).await.is_ok());
    // Another process revokes K: the renewed session here ends at its next request.
    let user = Uuid::parse_str(&session.user).unwrap();
    let mut third = wallet_auth(&db);
    third
        .revoke_wallet_device(user, key.verifying_key().to_bytes())
        .await
        .unwrap();
    assert_eq!(
        second.authenticate(&renewed.token, at).await.err(),
        Some(Error::Unauthorized)
    );
    // Anchored again, renewed, then logged out: no process renews the family any more.
    let (mut fourth, session, family) = member(&db).await;
    fourth
        .anchor_wallet_device(&session.token, key.verifying_key().to_bytes(), NOW)
        .await
        .unwrap();
    let renewed = renew(&mut fourth, &key, &session, family, at)
        .await
        .unwrap();
    fourth.logout(&renewed.token).await.unwrap();
    let mut fifth = wallet_auth(&db);
    assert_eq!(
        renew(&mut fifth, &key, &session, family, at + 60)
            .await
            .err(),
        Some(Error::Unauthorized)
    );
}

/// A renewed session refused because its family's anchor is gone names that check in the
/// development-gate refusal line (main's journey row 13 notes): `device_key_unanchored`, with
/// the grant's hashed ids and never the token. The outcome stays `Unauthorized`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renewed_session_without_its_anchor_names_the_check() {
    use crate::refusal::{
        scope,
        tests::{assert_shape, taken},
    };
    let (_directory, db) = wallet_database().await;
    let (mut auth, session, family) = member(&db).await;
    let key = SigningKey::from_bytes(&[9; 32]);
    auth.anchor_wallet_device(&session.token, key.verifying_key().to_bytes(), NOW)
        .await
        .unwrap();
    let at = NOW + 360;
    let renewed = renew(&mut auth, &key, &session, family, at).await.unwrap();
    // Another process revokes K; this one still holds the renewed session in memory.
    let user = Uuid::parse_str(&session.user).unwrap();
    wallet_auth(&db)
        .revoke_wallet_device(user, key.verifying_key().to_bytes())
        .await
        .unwrap();
    taken();
    let result = scope("initial_creation", auth.authenticate(&renewed.token, at)).await;
    assert_eq!(result.err(), Some(Error::Unauthorized));
    let lines = taken();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert_shape(line);
    assert!(line.contains("reason=device_key_unanchored "), "{line}");
    assert!(!line.contains("member=-"), "{line}");
    assert!(!line.contains(&renewed.token), "{line}");
}

/// Register a member and begin its next passkey login.
async fn wallet_login(db: &crlt::Db) -> (Auth, LoginFinish) {
    let mut auth = wallet_auth(db);
    let mut device = Resident::default();
    let begin = auth.register_begin(start(None), NOW).await.unwrap();
    let finish = registration(&mut device, begin).await;
    auth.register_finish(finish, NOW).await.unwrap();
    let finish = login(&mut auth, &mut device).await;
    (auth, finish)
}

fn proof(key: &SigningKey, ceremony: &str) -> Option<WalletDeviceProof> {
    Some(WalletDeviceProof {
        device_key: key.verifying_key().to_bytes(),
        signature: key
            .sign(&wallet_login_message(HOST, ceremony))
            .to_bytes()
            .to_vec(),
    })
}

/// M2: the wallet login with K's proof anchors its family inside the login when K is C's
/// current binding (M4), and names the family; K then renews it. An unbound K anchors nothing;
/// an invalid proof refuses the login and leaves no session; other logins refuse a proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wallet_login_with_the_device_proof_anchors_its_family() {
    let (_directory, db) = wallet_database().await;
    let key = SigningKey::from_bytes(&[11; 32]);
    let (mut auth, mut finish) = wallet_login(&db).await;
    finish.device_proof = proof(&key, &finish.ceremony);
    let seen = std::sync::Mutex::new(None);
    let session = auth
        .login_finish_wallet(finish, NOW, None, HOST, async |user, credential, k| {
            *seen.lock().unwrap() = Some((user, credential, k));
            Ok(true)
        })
        .await
        .unwrap();
    let family = auth.sessions[&session.token].family;
    assert_eq!(session.family, Some(family));
    let grant = auth.authenticate(&session.token, NOW).await.unwrap();
    assert_eq!(
        seen.into_inner().unwrap(),
        Some((grant.user, grant.credential, key.verifying_key().to_bytes()))
    );
    let renewed = renew(&mut auth, &key, &session, family, session.expires - 60)
        .await
        .unwrap();
    assert_eq!(renewed.family, Some(family));

    // K is not C's binding: the login stands, nothing is anchored, nothing renews.
    let (mut auth, mut finish) = wallet_login(&db).await;
    finish.device_proof = proof(&key, &finish.ceremony);
    let session = auth
        .login_finish_wallet(finish, NOW, None, HOST, async |_, _, _| Ok(false))
        .await
        .unwrap();
    assert_eq!(session.family, None);
    let family = auth.sessions[&session.token].family;
    assert_eq!(
        renew(&mut auth, &key, &session, family, session.expires - 60)
            .await
            .err(),
        Some(Error::Unauthorized)
    );

    // The binding read fails: the passkey login still stands, only unanchored.
    let (mut auth, mut finish) = wallet_login(&db).await;
    finish.device_proof = proof(&key, &finish.ceremony);
    let session = auth
        .login_finish_wallet(finish, NOW, None, HOST, async |_, _, _| {
            Err(Error::Unavailable)
        })
        .await
        .unwrap();
    assert_eq!(session.family, None);
    assert!(auth.authenticate(&session.token, NOW).await.is_ok());

    // A proof over another ceremony (or by another key) refuses the login: no session stays.
    let (mut auth, mut finish) = wallet_login(&db).await;
    finish.device_proof = proof(&key, "another ceremony");
    let before = auth.sessions.len();
    assert_eq!(
        auth.login_finish_wallet(finish, NOW, None, HOST, async |_, _, _| Ok(true))
            .await
            .err(),
        Some(Error::Unauthorized)
    );
    assert_eq!(auth.sessions.len(), before);

    // Only the wallet's login takes a proof.
    let (mut auth, mut finish) = wallet_login(&db).await;
    finish.device_proof = proof(&key, &finish.ceremony);
    assert_eq!(
        auth.login_finish(finish, NOW).await.err(),
        Some(Error::Invalid)
    );
}

/// Installs sharing one synced passkey derive one K: each holds its own family, at most
/// `ANCHORS_PER_KEY`; a further one evicts the oldest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_further_family_of_one_key_evicts_the_oldest() {
    let (_directory, db) = wallet_database().await;
    let (mut auth, mut device, first, first_family) = member_device(&db).await;
    let key = SigningKey::from_bytes(&[13; 32]);
    let k = key.verifying_key().to_bytes();
    auth.anchor_wallet_device(&first.token, k, NOW)
        .await
        .unwrap();
    let mut families = vec![(first, first_family)];
    for at in 1..=crate::wallet_session_anchors::ANCHORS_PER_KEY as u64 {
        let finish = login(&mut auth, &mut device).await;
        let session = auth.login_finish(finish, NOW).await.unwrap();
        let family = auth.sessions[&session.token].family;
        auth.anchor_wallet_device(&session.token, k, NOW + at)
            .await
            .unwrap();
        families.push((session, family));
    }
    let at = NOW + 600 - 60;
    let (oldest, family) = &families[0];
    assert_eq!(
        renew(&mut auth, &key, oldest, *family, at).await.err(),
        Some(Error::Unauthorized)
    );
    for (session, family) in &families[1..] {
        assert!(renew(&mut auth, &key, session, *family, at).await.is_ok());
    }
}

/// Revoking C, or rebinding C to another K, ends the families anchored through the old pair
/// at once (design 3.4), including their renewed sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_the_passkey_or_rebinding_it_ends_the_anchored_families() {
    let (_directory, db) = wallet_database().await;
    let key = SigningKey::from_bytes(&[15; 32]);
    let k = key.verifying_key().to_bytes();
    for rebind in [true, false] {
        let (mut auth, session, family) = member(&db).await;
        auth.anchor_wallet_device(&session.token, k, NOW)
            .await
            .unwrap();
        let at = session.expires - 60;
        let renewed = renew(&mut auth, &key, &session, family, at).await.unwrap();
        let grant = auth.authenticate(&session.token, at).await.unwrap();
        if rebind {
            // The current K stays; only C's other keys end.
            auth.rebind_wallet_device(grant.user, &grant.credential, k)
                .await
                .unwrap();
            assert!(auth.authenticate(&renewed.token, at).await.is_ok());
            auth.rebind_wallet_device(grant.user, &grant.credential, [16; 32])
                .await
                .unwrap();
        } else {
            auth.revoke_wallet_credential(grant.user, &[1; 16].as_slice().into())
                .await
                .unwrap();
            assert!(auth.authenticate(&renewed.token, at).await.is_ok());
            auth.revoke_wallet_credential(grant.user, &grant.credential)
                .await
                .unwrap();
        }
        assert_eq!(
            auth.authenticate(&renewed.token, at).await.err(),
            Some(Error::Unauthorized)
        );
        assert_eq!(
            renew(&mut auth, &key, &session, family, at).await.err(),
            Some(Error::Unauthorized)
        );
    }
}

/// A fork names its family exactly while the family is anchored, as its parent's login did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fork_names_the_family_only_while_it_is_anchored() {
    let (_directory, db) = wallet_database().await;
    let (mut auth, session, family) = member(&db).await;
    assert_eq!(auth.fork(&session.token, NOW).await.unwrap().family, None);
    auth.anchor_wallet_device(&session.token, [17; 32], NOW)
        .await
        .unwrap();
    assert_eq!(
        auth.fork(&session.token, NOW).await.unwrap().family,
        Some(family)
    );
}
