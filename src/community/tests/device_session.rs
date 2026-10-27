//! Device-key sessions: the nonce is single use, short lived and bound to its community, and
//! only an ACTIVE registered key of the member opens a session.
use super::*;
use crate::device_registry::{self, State};
use crate::device_session::message;
use crate::test_support::*;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

const HOST: &str = "api.alpha.example.test";
/// Public half of the key every fixture join binds first (`tests/support`, seed 13).
fn joined() -> [u8; 32] {
    key(13).verifying_key().to_bytes()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn finish(
    community: &str,
    challenge: &DeviceSessionChallenge,
    user: &str,
    signer: &SigningKey,
) -> DeviceSessionFinish {
    DeviceSessionFinish {
        nonce: challenge.nonce,
        user: user.into(),
        device_key: signer.verifying_key().to_bytes(),
        signature: signer
            .sign(&message(community, &challenge.nonce, challenge.issued))
            .to_bytes()
            .to_vec(),
    }
}
async fn fixture() -> (Running, Member, GlobalPublic) {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let member = enrol_community(&service, HOST, &passport).await;
    // The fixture member is a passkey member; give it the registered device key a join binds.
    let community = service.door.community_backend().unwrap().lock().await;
    device_registry::put(
        &community.db,
        "alpha",
        &member.user,
        &joined(),
        State::Active,
    )
    .await
    .unwrap();
    drop(community);
    (service, member, public)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_active_key_opens_and_silently_renews_a_session() {
    let (service, member, _) = fixture().await;
    // Over the real HTTP route, as a device does.
    let anonymous = client(&service, HOST, None);
    let challenge: DeviceSessionChallenge = serde_json::from_value(
        anonymous
            .call("device_session_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let request = finish("alpha", &challenge, &member.user, &key(13));
    let session: Session = serde_json::from_value(
        anonymous
            .call(
                "device_session_finish",
                serde_json::to_value(&request).unwrap(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(session.user, member.user);
    assert!(session.expires <= NOW + 3600);
    let mut community = service.door.community_backend().unwrap().lock().await;
    let (grant, authentication) = community.authenticate(&session.token, NOW).await.unwrap();
    assert_eq!(grant.user.to_string(), member.user);
    assert_eq!(grant.origin, ckyh::Origin::DeviceKey);
    assert_eq!(authentication.origin(), ckyh::Origin::DeviceKey);
    assert!(
        community
            .authenticate(&session.token, session.expires)
            .await
            .is_err()
    );
    // Renewal is the same exchange.
    let later = NOW + 1800;
    let challenge = community.device_session_begin(later).await.unwrap();
    let renewed = community
        .device_session_finish(finish("alpha", &challenge, &member.user, &key(13)), later)
        .await
        .unwrap();
    assert_ne!(renewed.token, session.token);
    assert!(renewed.expires > session.expires && renewed.expires <= later + 3600);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_revoked_and_pending_keys_are_refused() {
    let (service, member, _) = fixture().await;
    let mut community = service.door.community_backend().unwrap().lock().await;
    for (seed, state) in [
        (14, None),
        (15, Some(State::Revoked)),
        (16, Some(State::Pending)),
    ] {
        if let Some(state) = state {
            let public = key(seed).verifying_key().to_bytes();
            device_registry::put(&community.db, "alpha", &member.user, &public, state)
                .await
                .unwrap();
        }
        let challenge = community.device_session_begin(NOW).await.unwrap();
        let request = finish("alpha", &challenge, &member.user, &key(seed));
        assert!(matches!(
            community.device_session_finish(request, NOW).await,
            Err(Error::Unauthorized)
        ));
    }
    // A key that is active for the member, presented for another member, is refused too.
    let challenge = community.device_session_begin(NOW).await.unwrap();
    let other = ckyh::Uuid::new_v4().to_string();
    assert!(matches!(
        community
            .device_session_finish(finish("alpha", &challenge, &other, &key(13)), NOW)
            .await,
        Err(Error::Unauthorized)
    ));
    // A bad signature is refused and spends the nonce.
    let challenge = community.device_session_begin(NOW).await.unwrap();
    let mut request = finish("alpha", &challenge, &member.user, &key(13));
    request.signature[0] ^= 1;
    assert!(community.device_session_finish(request, NOW).await.is_err());
    assert!(
        community
            .device_session_finish(finish("alpha", &challenge, &member.user, &key(13)), NOW)
            .await
            .is_err()
    );
    // A revoked key stops working even though its session was opened while it was active.
    let challenge = community.device_session_begin(NOW).await.unwrap();
    let session = community
        .device_session_finish(finish("alpha", &challenge, &member.user, &key(13)), NOW)
        .await
        .unwrap();
    device_registry::put(
        &community.db,
        "alpha",
        &member.user,
        &joined(),
        State::Revoked,
    )
    .await
    .unwrap();
    assert!(community.authenticate(&session.token, NOW).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nonce_is_single_use_expires_and_belongs_to_one_community() {
    let (service, member, public) = fixture().await;
    let beta = community_unfounded("beta", &public).await;
    let mut community = service.door.community_backend().unwrap().lock().await;
    let challenge = community.device_session_begin(NOW).await.unwrap();
    let request = || finish("alpha", &challenge, &member.user, &key(13));
    community
        .device_session_finish(request(), NOW)
        .await
        .unwrap();
    assert!(matches!(
        community.device_session_finish(request(), NOW).await,
        Err(Error::Unauthorized)
    ));
    // Expired: refused exactly at the limit, and pruned.
    let challenge = community.device_session_begin(NOW).await.unwrap();
    assert!(
        community
            .device_session_finish(
                finish("alpha", &challenge, &member.user, &key(13)),
                NOW + 60
            )
            .await
            .is_err()
    );
    // A nonce issued by another community is unknown here, and signed for it is wrong here.
    let mut other = beta.door.community_backend().unwrap().lock().await;
    let foreign = other.device_session_begin(NOW).await.unwrap();
    assert!(
        community
            .device_session_finish(finish("beta", &foreign, &member.user, &key(13)), NOW)
            .await
            .is_err()
    );
    let local = community.device_session_begin(NOW).await.unwrap();
    assert!(
        community
            .device_session_finish(finish("beta", &local, &member.user, &key(13)), NOW)
            .await
            .is_err()
    );
    // Bounded: the pending nonces never exceed the configured capacity.
    community.config.pending_capacity = 1;
    community.device_nonces.clear();
    community.device_session_begin(NOW).await.unwrap();
    assert!(matches!(
        community.device_session_begin(NOW).await,
        Err(Error::Throttled)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn communities_keep_separate_device_keys_for_the_same_member() {
    let (service, member, _) = fixture().await;
    let community = service.door.community_backend().unwrap().lock().await;
    let b = key(22).verifying_key().to_bytes();
    device_registry::put(&community.db, "beta", &member.user, &b, State::Active)
        .await
        .unwrap();
    let state = |scope: &'static str, key: [u8; 32]| {
        let db = community.db.clone();
        let user = member.user.clone();
        async move {
            device_registry::state(&db, scope, &user, &key)
                .await
                .unwrap()
        }
    };
    assert_eq!(state("alpha", joined()).await, Some(State::Active));
    assert_eq!(state("alpha", b).await, None);
    assert_eq!(state("beta", b).await, Some(State::Active));
    assert_eq!(state("beta", joined()).await, None);
    // Alpha's membership sees only alpha's registry.
    let user = ckyh::Uuid::parse_str(&member.user).unwrap();
    let membership = community.facade.membership();
    assert_eq!(
        membership.device_key_state(user, joined()).await.unwrap(),
        Some(State::Active)
    );
    assert_eq!(membership.device_key_state(user, b).await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_session_is_a_full_member_session_except_for_human_confirmations() {
    let (service, member, _) = fixture().await;
    let anonymous = client(&service, HOST, None);
    let challenge: DeviceSessionChallenge = serde_json::from_value(
        anonymous
            .call("device_session_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let request = finish("alpha", &challenge, &member.user, &key(13));
    let session: Session = serde_json::from_value(
        anonymous
            .call(
                "device_session_finish",
                serde_json::to_value(&request).unwrap(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let device = client(&service, HOST, Some(&session.token));
    let passkey = client(&service, HOST, Some(&member.session));
    // Same member, same role, same community: the lobby view is identical whatever the origin.
    assert_eq!(
        device.call("lobby", json!({})).await.unwrap(),
        passkey.call("lobby", json!({})).await.unwrap()
    );
    // Human confirmations stay passkey-only until the confirmation stamp exists.
    let action = json!({"kind":"device_authorize","key":joined()});
    assert!(
        device
            .call("step_up_begin", json!({"action": action}))
            .await
            .is_err()
    );
    assert!(
        passkey
            .call("step_up_begin", json!({"action": action}))
            .await
            .is_ok()
    );
    assert!(device.call("passkey_list", json!({})).await.is_err());
}

/// The record source and every other lease probe uses `lobby` (a Member read that device-key
/// and passkey sessions may both make): it answers 401 once the session's lease or its device
/// is no longer current, and it grants nothing the session did not already have.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lobby_read_is_a_lease_probe_for_device_and_passkey_sessions() {
    let (service, member, _) = fixture().await;
    let anonymous = client(&service, HOST, None);
    let challenge: DeviceSessionChallenge = serde_json::from_value(
        anonymous
            .call("device_session_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let request = finish("alpha", &challenge, &member.user, &key(13));
    let session: Session = serde_json::from_value(
        anonymous
            .call(
                "device_session_finish",
                serde_json::to_value(&request).unwrap(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let device = client(&service, HOST, Some(&session.token));
    let passkey = client(&service, HOST, Some(&member.session));
    assert!(device.call("lobby", json!({})).await.is_ok());
    assert!(passkey.call("lobby", json!({})).await.is_ok());
    // An expired lease is refused.
    {
        let mut community = service.door.community_backend().unwrap().lock().await;
        assert!(
            community
                .authenticate(&session.token, session.expires)
                .await
                .is_err()
        );
    }
    // A revoked device is refused although its session was opened while it was active.
    {
        let mut community = service.door.community_backend().unwrap().lock().await;
        device_registry::put(
            &community.db,
            "alpha",
            &member.user,
            &joined(),
            State::Revoked,
        )
        .await
        .unwrap();
    }
    assert!(device.call("lobby", json!({})).await.is_err());
}

/// The lobby read answers a transient membership storage failure as `Unavailable` (503: the
/// device retries and keeps its keys) and a genuine denial as `Refused`. A device turns a
/// refused lobby into a lock of its keys, so a busy or failed store must never read as one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lobby_read_reports_a_transient_store_failure_as_unavailable() {
    let (service, member, _) = fixture().await;
    let anonymous = client(&service, HOST, None);
    let challenge: DeviceSessionChallenge = serde_json::from_value(
        anonymous
            .call("device_session_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let request = finish("alpha", &challenge, &member.user, &key(13));
    let session: Session = serde_json::from_value(
        anonymous
            .call(
                "device_session_finish",
                serde_json::to_value(&request).unwrap(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let mut community = service.door.community_backend().unwrap().lock().await;
    let now = NOW;
    let (_, auth) = community.authenticate(&session.token, now).await.unwrap();
    assert!(community.lobby(&auth, now).await.is_ok());
    // The member's enrolment row becomes unreadable for a moment (a failed store).
    let mut tx = community.db.tx("alpha").await.unwrap();
    let rows = tx
        .query(
            "SELECT payload FROM cnrl_enrolments WHERE user_id = ?1",
            crlt::params![member.user.clone()],
        )
        .await
        .unwrap();
    let payload = rows[0].get_str(0).unwrap().to_owned();
    tx.execute(
        "UPDATE cnrl_enrolments SET payload = ?1 WHERE user_id = ?2",
        crlt::params!["unreadable".to_owned(), member.user.clone()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        community.lobby(&auth, now).await.err(),
        Some(Error::Unavailable)
    );
    let mut tx = community.db.tx("alpha").await.unwrap();
    tx.execute(
        "UPDATE cnrl_enrolments SET payload = ?1 WHERE user_id = ?2",
        crlt::params![payload, member.user.clone()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(community.lobby(&auth, now).await.is_ok());
    // A genuine denial stays a refusal: the key is revoked.
    device_registry::put(
        &community.db,
        "alpha",
        &member.user,
        &joined(),
        State::Revoked,
    )
    .await
    .unwrap();
    assert_eq!(
        community.lobby(&auth, now).await.err(),
        Some(Error::Refused)
    );
}
