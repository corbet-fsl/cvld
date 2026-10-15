//! Join by device key with ONE wallet confirmation: the wallet issues a blind stamp after one
//! user verification of its passkey over the exact request; the community binds the member's
//! first device key from a passport presentation plus that stamp, with no community passkey,
//! and the key then opens sessions silently.
use super::*;
use crate::device_session::{JOIN_ACTION, join_message, message};
use crate::test_support::*;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use webauthn_authenticator_rs::AuthenticatorBackend as _;

const HOST: &str = "api.alpha.example.test";

struct Wallet {
    member: Member,
    holder: cpsd::OpaqueHolder,
}

async fn wallet(global: &Running, seed: u8) -> Wallet {
    let member = enrol(global, WALLET, None).await;
    let client = client(global, WALLET, Some(&member.session));
    client.call("development_gate", json!({})).await.unwrap();
    let public: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [seed; 32]);
    let challenge: Bytes =
        serde_json::from_value(client.call("passport_challenge", json!({})).await.unwrap())
            .unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let request = holder
        .begin_issuance(&mut cpsd::rand::rngs::OsRng, &issuer, &challenge)
        .unwrap();
    let response: Bytes = serde_json::from_value(
        client
            .call(
                "passport_issue",
                json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes()}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    holder
        .finish_issuance(&cpsd::BlindPassport::from_bytes(&response.bytes).unwrap())
        .unwrap();
    Wallet { member, holder }
}

/// One user-verifying assertion of the wallet passkey over exactly `challenge`, from the
/// options the wallet's stamp challenge carries.
async fn confirm(wallet: &mut Wallet, options: &Value, challenge: [u8; 32]) -> Value {
    let mut options: ckyh::RequestChallengeResponse =
        serde_json::from_value(options.clone()).unwrap();
    options.public_key.challenge = challenge.to_vec().into();
    let credential = wallet
        .member
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&origin_for(WALLET)).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap();
    let public: ckyh::PublicKeyCredential =
        serde_json::from_value(serde_json::to_value(&credential).unwrap()).unwrap();
    json!({
        "credential_id": public.raw_id.as_ref().to_vec(),
        "client_data_json": public.response.client_data_json.as_ref().to_vec(),
        "authenticator_data": public.response.authenticator_data.as_ref().to_vec(),
        "signature": public.response.signature.as_ref().to_vec(),
        "user_handle": public.response.user_handle.as_ref().map(|h| h.as_ref().to_vec()),
    })
}

fn scope(community: &str) -> cpsd::StampScope {
    scope_of(community, None)
}

/// The device's stamp scope: SHA-256 of the founding document from the trust feed, or the
/// unfounded tag and id.
fn scope_of(community: &str, genesis: Option<&[u8]>) -> cpsd::StampScope {
    use sha2::Digest as _;
    let digest = match genesis {
        Some(genesis) => sha2::Sha256::digest(genesis),
        None => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(crate::device_session::UNFOUNDED_FINGERPRINT_TAG);
            hasher.update(community.as_bytes());
            hasher.finalize()
        }
    };
    cpsd::StampScope::new(
        cpsd::CommunityId::new(community).unwrap(),
        cpsd::CommunityFingerprint::from_bytes(digest.into()),
    )
}

async fn community_scope(service: &Running, community: &str) -> cpsd::StampScope {
    let feed: TrustFeed = serde_json::from_value(
        client(service, HOST, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    scope_of(community, feed.genesis.as_deref())
}

fn join_action(key: &[u8; 32], salt: [u8; 32]) -> cpsd::StampAction {
    cpsd::StampAction::new(
        cpsd::ActionKind::new(JOIN_ACTION).unwrap(),
        cpsd::PayloadDigest::from_bytes(*key),
        cpsd::StampSalt::from_bytes(salt),
    )
}

/// The one confirmation: a stamp covering `actions`, issued blindly by the wallet.
async fn stamp(
    global: &Running,
    wallet: &mut Wallet,
    actions: &[(cpsd::StampScope, cpsd::StampAction)],
) {
    let client = client(global, WALLET, Some(&wallet.member.session));
    let reserved: crate::api::StampChallenge =
        serde_json::from_value(client.call("stamp_challenge", json!({})).await.unwrap()).unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(reserved.challenge.try_into().unwrap());
    let key = cpsd::StampPublicKey::from_bytes(&reserved.key).unwrap();
    let request = wallet
        .holder
        .begin_stamp(&mut cpsd::rand::rngs::OsRng, &key, &challenge, actions, NOW)
        .unwrap();
    let assertion = confirm(
        wallet,
        &reserved.options,
        request.confirmation_challenge(&challenge),
    )
    .await;
    let blind: Bytes = serde_json::from_value(
        client
            .call(
                "stamp_issue",
                json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes(),"assertion":assertion}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    wallet
        .holder
        .finish_stamp(&cpsd::BlindStamp::from_bytes(&blind.bytes).unwrap(), NOW)
        .unwrap();
}

async fn join_body(
    service: &Running,
    wallet: &Wallet,
    community: &str,
    device: &SigningKey,
    salt: [u8; 32],
) -> Value {
    let challenge: PresentationChallenge = serde_json::from_value(
        client(service, HOST, None)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let feed: TrustFeed = serde_json::from_value(
        client(service, HOST, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new(community).unwrap(),
        csgn::KeyRing::from_cbor(&feed.key_ring).unwrap(),
    );
    let proof = wallet
        .holder
        .present(
            &mut cpsd::rand::rngs::OsRng,
            &expected,
            &challenge.request,
            NOW,
        )
        .unwrap();
    let key = device.verifying_key().to_bytes();
    let presentation = wallet
        .holder
        .present_stamp(
            &mut cpsd::rand::rngs::OsRng,
            &scope_of(community, feed.genesis.as_deref()),
            &join_action(&key, salt),
            NOW,
        )
        .unwrap();
    json!({
        "passport": {"challenge": challenge.challenge, "proof": proof.to_bytes()},
        "stamp": presentation.to_bytes(),
        "salt": salt,
        "device_key": key,
        "signature": device.sign(&join_message(community, &challenge.challenge, &key)).to_bytes().to_vec(),
    })
}

async fn open_session(service: &Running, user: &str, device: &SigningKey) -> Result<Session> {
    let anonymous = client(service, HOST, None);
    let challenge: DeviceSessionChallenge = serde_json::from_value(
        anonymous
            .call("device_session_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let request = DeviceSessionFinish {
        nonce: challenge.nonce,
        user: user.into(),
        device_key: device.verifying_key().to_bytes(),
        signature: device
            .sign(&message("alpha", &challenge.nonce, challenge.issued))
            .to_bytes()
            .to_vec(),
    };
    anonymous
        .call(
            "device_session_finish",
            serde_json::to_value(&request).unwrap(),
        )
        .await
        .map(|value| serde_json::from_value(value).unwrap())
        .map_err(|_| Error::Unauthorized)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_wallet_confirmation_joins_by_device_key_and_opens_sessions_without_a_community_passkey()
 {
    let global = configured_wallet(100).await;
    let mut wallet = wallet(&global, 61).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let service = community("alpha", &public).await;
    let device = SigningKey::from_bytes(&[71; 32]);
    let key = device.verifying_key().to_bytes();
    let salt = [9; 32];
    let scope = community_scope(&service, "alpha").await;
    stamp(&global, &mut wallet, &[(scope, join_action(&key, salt))]).await;
    let body = join_body(&service, &wallet, "alpha", &device, salt).await;
    let joined: crate::api::DeviceJoined = serde_json::from_value(
        client(&service, HOST, None)
            .call("device_join", body)
            .await
            .unwrap(),
    )
    .unwrap();
    // Silent sessions by the bound key; it is a full member session.
    let session = open_session(&service, &joined.user, &device).await.unwrap();
    assert_eq!(session.user, joined.user);
    client(&service, HOST, Some(&session.token))
        .call("lobby", json!({}))
        .await
        .unwrap();
    // A retry of the same join (lost response) returns the same member, no new confirmation.
    let again = join_body(&service, &wallet, "alpha", &device, salt).await;
    let rejoined: crate::api::DeviceJoined = serde_json::from_value(
        client(&service, HOST, None)
            .call("device_join", again)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rejoined.user, joined.user);
    // The stamp covers exactly this key: another key is refused.
    let other = SigningKey::from_bytes(&[72; 32]);
    let mut wrong = join_body(&service, &wallet, "alpha", &device, salt).await;
    let other_key = other.verifying_key().to_bytes();
    wrong["device_key"] = json!(other_key);
    assert!(
        client(&service, HOST, None)
            .call("device_join", wrong)
            .await
            .is_err()
    );
    // Without a stamp nothing joins.
    let mut unstamped = join_body(&service, &wallet, "alpha", &device, salt).await;
    unstamped["salt"] = json!(vec![8u8; 32]);
    assert!(
        client(&service, HOST, None)
            .call("device_join", unstamped)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stamp_needs_the_exact_user_verification_and_the_members_own_passport() {
    let global = configured_wallet(100).await;
    let mut wallet = wallet(&global, 62).await;
    let client = client(&global, WALLET, Some(&wallet.member.session));
    let reserved: crate::api::StampChallenge =
        serde_json::from_value(client.call("stamp_challenge", json!({})).await.unwrap()).unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(reserved.challenge.try_into().unwrap());
    let key = cpsd::StampPublicKey::from_bytes(&reserved.key).unwrap();
    let action = join_action(&[5; 32], [1; 32]);
    let request = wallet
        .holder
        .begin_stamp(
            &mut cpsd::rand::rngs::OsRng,
            &key,
            &challenge,
            &[(scope("alpha"), action)],
            NOW,
        )
        .unwrap();
    // An assertion over another challenge is refused.
    let wrong = confirm(&mut wallet, &reserved.options, [0; 32]).await;
    assert!(
        client
            .call(
                "stamp_issue",
                json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes(),"assertion":wrong}),
            )
            .await
            .is_err()
    );
    // Another person's secret (a holder without this member's passport) is refused.
    let mut stranger = cpsd::OpaqueHolder::from_seed(&mut [63; 32]);
    let foreign = stranger
        .begin_stamp(
            &mut cpsd::rand::rngs::OsRng,
            &key,
            &challenge,
            &[(scope("alpha"), join_action(&[5; 32], [1; 32]))],
            NOW,
        )
        .unwrap();
    let assertion = confirm(
        &mut wallet,
        &reserved.options,
        foreign.confirmation_challenge(&challenge),
    )
    .await;
    assert!(
        client
            .call(
                "stamp_issue",
                json!({"challenge":challenge.to_bytes().to_vec(),"request":foreign.to_bytes(),"assertion":assertion}),
            )
            .await
            .is_err()
    );
    // The right confirmation issues exactly once.
    let assertion = confirm(
        &mut wallet,
        &reserved.options,
        request.confirmation_challenge(&challenge),
    )
    .await;
    let body = json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes(),"assertion":assertion});
    client.call("stamp_issue", body.clone()).await.unwrap();
    assert!(client.call("stamp_issue", body).await.is_err());
}
