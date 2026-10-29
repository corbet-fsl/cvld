//! A13: wallet session renewal by the wallet device key K (secure convenience, M1-M4).
//! Written red first; the API named here is the one the implementation provides:
//! `Auth::wallet_renew_begin`, `Auth::wallet_renew`, the anchor written at login (M2) and
//! removed by revocation, and the binding check at renewal (M4, `bound`).
use super::*;
use crate::device_session::wallet_message;
use ed25519_dalek::{Signer, SigningKey};

const HOST: &str = "wallet.example.test";

async fn member(db: &crlt::Db) -> (Auth, Session, [u8; 32]) {
    let mut member = auth(db, None, 16);
    let mut device = Resident::default();
    let begin = member.register_begin(start(None), NOW).await.unwrap();
    let finish = registration(&mut device, begin).await;
    member.register_finish(finish, NOW).await.unwrap();
    let finish = login(&mut member, &mut device).await;
    let session = member.login_finish(finish, NOW).await.unwrap();
    let family = member.sessions[&session.token].family;
    (member, session, family)
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
fn bound_to(key: &SigningKey) -> impl Fn(Uuid, &ckyh::CredentialID, [u8; 32]) -> bool {
    let expected = key.verifying_key().to_bytes();
    move |_, _, device| device == expected
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anchored_device_key_renews_the_wallet_session_without_a_prompt() {
    let (_directory, db) = database().await;
    let (mut auth, session, family) = member(&db).await;
    let key = SigningKey::from_bytes(&[7; 32]);
    auth.anchor_wallet_device(&session.token, key.verifying_key().to_bytes(), NOW)
        .await
        .unwrap();
    let at = session.expires - 60;
    let challenge = auth.wallet_renew_begin(at).await.unwrap();
    let renewed = auth
        .wallet_renew(HOST, renewal(&key, &session, family, &challenge), at, &bound_to(&key))
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
            &bound_to(&key),
        )
        .await
        .unwrap();
    assert!(again.expires > renewed.expires);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_device_key_is_refused() {
    let (_directory, db) = database().await;
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
        auth.wallet_renew(HOST, renewal(&key, &session, family, &challenge), at, &bound_to(&key))
            .await
            .err(),
        Some(Error::Unauthorized)
    );
    // Revocation also ends the families the key renewed.
    assert!(auth.authenticate(&session.token, NOW + 1).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_key_never_anchored_is_refused() {
    let (_directory, db) = database().await;
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
            &|_, _, _| true,
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
            &bound_to(&anchored),
        )
        .await
        .err(),
        Some(Error::Unauthorized)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renewal_keeps_the_binding_and_refuses_an_unbound_key() {
    let (_directory, db) = database().await;
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
            &|_, _, _| false,
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
            &|user, credential: &ckyh::CredentialID, k| {
                *seen.lock().unwrap() = Some((user, credential.clone(), k));
                true
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
            &bound_to(&key),
        )
        .await
        .err(),
        Some(Error::Unauthorized)
    );
}
