//! Join by device key with ONE wallet confirmation: the wallet issues a blind stamp after one
//! user verification of its passkey over the exact request; the community binds the member's
//! first device key from a passport presentation plus that stamp, with no community passkey,
//! and the key then opens sessions silently.
use super::device_session::DEFAULT_STAMP_COHORT_SECONDS;
use super::*;
use crate::device_session::{
    ACTIVATE_ACTION, ADD_ACTION, JOIN_ACTION, PAIR_ACTION, approval_message, garden_message,
    join_message, join_payload, message, pair_payload, pairing_message,
};
use crate::test_support::*;
use cmty::cmbr::PAIRING_PENDING_SECONDS;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use webauthn_authenticator_rs::AuthenticatorBackend as _;

const HOST: &str = "api.alpha.example.test";

/// The API host of a community of these tests.
fn host(community: &str) -> String {
    format!("api.{community}.example.test")
}

/// A device key that signs join and session messages: a plain ed25519 key, or the Keys device
/// of a real first lineage (whose receipt the genesis stamp covers).
trait Device {
    fn key(&self) -> [u8; 32];
    async fn sign(&mut self, message: &[u8]) -> Vec<u8>;
}
impl Device for SigningKey {
    fn key(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
    async fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        ed25519_dalek::Signer::sign(self, message)
            .to_bytes()
            .to_vec()
    }
}

#[derive(Clone, Default)]
struct KeysStore(
    std::rc::Rc<std::cell::RefCell<std::collections::HashMap<ckmg::Locator, Vec<u8>>>>,
);
impl ckmg::SecureStore for KeysStore {
    async fn load(
        &mut self,
        location: &ckmg::Locator,
    ) -> std::result::Result<Option<Vec<u8>>, ckmg::Error> {
        Ok(self.0.borrow().get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &ckmg::Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> std::result::Result<ckmg::Commit, ckmg::Error> {
        let mut records = self.0.borrow_mut();
        if records
            .get(location)
            .map(|value| *blake3::hash(value).as_bytes())
            != expected
        {
            return Ok(ckmg::Commit::Conflict);
        }
        records.insert(*location, replacement.to_vec());
        Ok(ckmg::Commit::Committed)
    }
}
struct KeysClock;
impl ckmg::Clock for KeysClock {
    fn now(&mut self) -> std::result::Result<u64, ckmg::Error> {
        Ok(NOW)
    }
}
/// Test-only lineage authority: every request of this one binding (no production G3).
struct KeysAuthority(ckmg::Binding);
impl ckmg::Authority for KeysAuthority {
    async fn check(
        &mut self,
        request: ckmg::Authorization<'_>,
    ) -> std::result::Result<(), ckmg::Error> {
        if request.binding != &self.0 {
            return Err(ckmg::Error::Unauthorized);
        }
        Ok(())
    }
}

/// The member's first community lineage made by Keys on the device: the `Created` receipt and
/// the device key that signed it, which also joins and opens the member's sessions. Device
/// signatures are typed: the join and the session are signed the way a device-key member
/// signs them before activation, by its enrollment candidate (the same PRF-derived key).
struct KeysDevice {
    _keys: ckmg::Keys<KeysStore, KeysClock, ckmg::SystemEntropy, KeysAuthority>,
    candidate: ckmg::UnenrolledCreation,
    key: [u8; 32],
    receipt: ckmg::Receipt,
}
impl Device for KeysDevice {
    fn key(&self) -> [u8; 32] {
        self.key
    }
    async fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        let format = ckmg::DeviceFormat::of(message).unwrap();
        self.candidate
            .sign_device(format, &message[format.tag().len()..])
            .unwrap()
            .to_vec()
    }
}
async fn keys_device(community: &str, member: &str) -> KeysDevice {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[27; 32]).unwrap();
    let binding = ckmg::Binding::new(community, member).unwrap();
    let mut keys = ckmg::Keys::new(
        KeysStore::default(),
        KeysClock,
        ckmg::SystemEntropy,
        KeysAuthority(binding.clone()),
    );
    let receipt = keys
        .create_scope(
            &prf,
            binding,
            ckmg::DeviceInfo::new("fixture", &[7; 16]).unwrap(),
            b"fixture",
        )
        .await
        .unwrap();
    keys.acknowledge(receipt.operation).await.unwrap();
    keys.unlock(&prf, community).await.unwrap();
    let key = *keys.device_public_key().await.unwrap().value();
    assert_eq!(*receipt.attested_lineage().unwrap().1.value(), key);
    let candidate = ckmg::EnrollmentSeed::new(
        ckmg::Binding::new(community, member).unwrap(),
        &mut ckmg::SystemEntropy,
    )
    .unwrap()
    .seal(
        &prf,
        ckmg::DeviceInfo::new("fixture", &[7; 16]).unwrap(),
        &mut KeysClock,
        &mut ckmg::SystemEntropy,
    )
    .unwrap();
    KeysDevice {
        _keys: keys,
        candidate,
        key,
        receipt,
    }
}

struct Wallet {
    member: Member,
    holder: cpsd::OpaqueHolder,
}

async fn wallet(global: &Running, seed: u8) -> Wallet {
    wallet_of(global, enrol(global, WALLET, None).await, seed).await
}

async fn wallet_of(global: &Running, member: Member, seed: u8) -> Wallet {
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

/// The device's stamp scope: the founding fingerprint of the founding document from the trust
/// feed (the verified Charter's fingerprint), or the unfounded tag and id.
fn scope_of(community: &str, genesis: Option<&[u8]>) -> cpsd::StampScope {
    let founding = genesis.map(|genesis| csgn::verify_genesis(genesis).unwrap().fingerprint());
    cpsd::StampScope::of_community(
        cpsd::CommunityId::new(community).unwrap(),
        founding.as_ref(),
    )
}

async fn community_scope(service: &Running, community: &str) -> cpsd::StampScope {
    let feed: TrustFeed = serde_json::from_value(
        client(service, &host(community), None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    scope_of(community, feed.genesis.as_deref())
}

/// The member's opaque initial creation commitment in these tests.
const SEED: [u8; 32] = [33; 32];

fn join_action(key: &[u8; 32], salt: [u8; 32]) -> cpsd::StampAction {
    join_action_for(key, &SEED, salt)
}

fn join_action_for(key: &[u8; 32], seed: &[u8; 32], salt: [u8; 32]) -> cpsd::StampAction {
    cpsd::StampAction::new(
        cpsd::ActionKind::new(JOIN_ACTION).unwrap(),
        cpsd::PayloadDigest::from_bytes(join_payload(key, seed)),
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
    // The device expects the epoch of the signed global status, not one from the reply.
    let public: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let epoch = cchr::global_stamp_trust(&public.key_ring, &public.status, NOW)
        .unwrap()
        .epoch()
        .unwrap();
    wallet
        .holder
        .finish_stamp(
            &cpsd::BlindStamp::from_bytes(&blind.bytes).unwrap(),
            epoch,
            NOW,
        )
        .unwrap();
}

async fn join_body(
    service: &Running,
    wallet: &Wallet,
    community: &str,
    device: &mut impl Device,
    salt: [u8; 32],
) -> Value {
    join_body_with(service, wallet, community, device, salt, true).await
}

/// A join body; without `stamped` its stamp is empty (a stamp that no longer verifies).
async fn join_body_with(
    service: &Running,
    wallet: &Wallet,
    community: &str,
    device: &mut impl Device,
    salt: [u8; 32],
    stamped: bool,
) -> Value {
    let challenge: PresentationChallenge = serde_json::from_value(
        client(service, &host(community), None)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let feed: TrustFeed = serde_json::from_value(
        client(service, &host(community), None)
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
    let key = device.key();
    let presentation = if stamped {
        wallet
            .holder
            .present_stamp(
                &mut cpsd::rand::rngs::OsRng,
                &scope_of(community, feed.genesis.as_deref()),
                &join_action(&key, salt),
                NOW,
            )
            .unwrap()
            .to_bytes()
    } else {
        Vec::new()
    };
    json!({
        "passport": {"challenge": challenge.challenge, "proof": proof.to_bytes()},
        "stamp": presentation,
        "salt": salt,
        "device_key": key,
        "seed": SEED,
        "signature": device.sign(&join_message(community, &challenge.challenge, &key)).await,
    })
}

async fn open_session(service: &Running, user: &str, device: &mut impl Device) -> Result<Session> {
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
        device_key: device.key(),
        signature: device
            .sign(&message("alpha", &challenge.nonce, challenge.issued))
            .await,
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
    let mut device = SigningKey::from_bytes(&[71; 32]);
    let key = device.verifying_key().to_bytes();
    let salt = [9; 32];
    let scope = community_scope(&service, "alpha").await;
    stamp(&global, &mut wallet, &[(scope, join_action(&key, salt))]).await;
    // Without a stamp nothing joins: the stamp covers exactly this salt, and before the join
    // is applied there is nothing to re-confirm (after it, the same key and seed are
    // re-confirmed, below).
    let mut unstamped = join_body(&service, &wallet, "alpha", &mut device, salt).await;
    unstamped["salt"] = json!(vec![8u8; 32]);
    assert!(
        client(&service, HOST, None)
            .call("device_join", unstamped)
            .await
            .is_err()
    );
    let body = join_body(&service, &wallet, "alpha", &mut device, salt).await;
    let joined: crate::api::DeviceJoined = serde_json::from_value(
        client(&service, HOST, None)
            .call("device_join", body)
            .await
            .unwrap(),
    )
    .unwrap();
    // Silent sessions by the bound key; it is a full member session.
    let session = open_session(&service, &joined.user, &mut device)
        .await
        .unwrap();
    assert_eq!(session.user, joined.user);
    client(&service, HOST, Some(&session.token))
        .call("lobby", json!({}))
        .await
        .unwrap();
    // A retry of the same join (lost response) returns the same member, no new confirmation.
    let again = join_body(&service, &wallet, "alpha", &mut device, salt).await;
    let rejoined: crate::api::DeviceJoined = serde_json::from_value(
        client(&service, HOST, None)
            .call("device_join", again)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rejoined.user, joined.user);
    // Once no stamp verifies any more (its cohort ended; here none is sent), the SAME applied
    // join is re-confirmed from the member's state with a fresh passport and key signature:
    // a device interrupted after the join never needs a second confirmation.
    let uses = stamp_uses(&service).await;
    let stampless = join_body_with(&service, &wallet, "alpha", &mut device, salt, false).await;
    let reconfirmed: crate::api::DeviceJoined = serde_json::from_value(
        client(&service, HOST, None)
            .call("device_join", stampless)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reconfirmed.user, joined.user);
    assert_eq!(stamp_uses(&service).await, uses);
    // A join that was never applied is not re-confirmed: another key without a stamp.
    let mut stranger = SigningKey::from_bytes(&[73; 32]);
    let stampless = join_body_with(&service, &wallet, "alpha", &mut stranger, salt, false).await;
    assert!(
        client(&service, HOST, None)
            .call("device_join", stampless)
            .await
            .is_err()
    );
    // The stamp covers exactly this key: another key is refused.
    let other = SigningKey::from_bytes(&[72; 32]);
    let mut wrong = join_body(&service, &wallet, "alpha", &mut device, salt).await;
    let other_key = other.verifying_key().to_bytes();
    wrong["device_key"] = json!(other_key);
    assert!(
        client(&service, HOST, None)
            .call("device_join", wrong)
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
    // The right confirmation issues once; the SAME request again (a device killed after the
    // reply, before it stored the stamp) gets the SAME stamp without a new user verification,
    // even with an assertion over another challenge.
    let assertion = confirm(
        &mut wallet,
        &reserved.options,
        request.confirmation_challenge(&challenge),
    )
    .await;
    let body = json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes(),"assertion":assertion});
    let issued = client.call("stamp_issue", body.clone()).await.unwrap();
    assert_eq!(client.call("stamp_issue", body).await.unwrap(), issued);
    let unverified = json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes(),"assertion":wrong});
    assert_eq!(
        client.call("stamp_issue", unverified).await.unwrap(),
        issued
    );
    // A different request is never a replay: it needs its own confirmation.
    assert!(
        client
            .call(
                "stamp_issue",
                json!({"challenge":challenge.to_bytes().to_vec(),"request":foreign.to_bytes(),"assertion":wrong}),
            )
            .await
            .is_err()
    );
}

/// Recorded one-use stamp digests of the community `alpha`.
async fn stamp_uses(service: &Running) -> i64 {
    let community = service.door.community_backend().unwrap().lock().await;
    let mut tx = community.db.community("alpha").unwrap().tx().await.unwrap();
    let rows = tx
        .query("SELECT COUNT(*) FROM cvld_stamp_uses", ())
        .await
        .unwrap();
    let count = rows.first().unwrap().get_i64(0).unwrap();
    tx.rollback().await.unwrap();
    count
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_joined_device_key_holds_the_stamped_creation_commitment_and_binds_one_publication() {
    let global = configured_wallet(100).await;
    let mut wallet = wallet(&global, 64).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let service = community("alpha", &public).await;
    let pseudonym = wallet
        .holder
        .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
        .to_hex();
    // The device makes the member's first lineage locally; its Keys device key joins.
    let mut device = keys_device("alpha", &pseudonym).await;
    let key = device.key();
    let salt = [11; 32];
    let scope = community_scope(&service, "alpha").await;
    // ONE stamp, two slots of this community: the join and the lineage genesis of the
    // device's first receipt; the join presents only its own slot.
    let genesis_salt = [12; 32];
    let genesis = cchr::lineage_genesis_action(&device.receipt, genesis_salt, NOW).unwrap();
    stamp(
        &global,
        &mut wallet,
        &[
            (scope.clone(), join_action(&key, salt)),
            (scope.clone(), genesis.clone()),
        ],
    )
    .await;
    assert!(wallet.holder.stamp_covers(&scope, &genesis, NOW));
    // A seed other than the stamped one is refused (the payload digest differs).
    let mut forged = join_body(&service, &wallet, "alpha", &mut device, salt).await;
    forged["seed"] = json!(vec![34u8; 32]);
    assert!(
        client(&service, HOST, None)
            .call("device_join", forged)
            .await
            .is_err()
    );
    // A zero seed is refused outright.
    let mut zero = join_body(&service, &wallet, "alpha", &mut device, salt).await;
    zero["seed"] = json!(vec![0u8; 32]);
    assert!(
        client(&service, HOST, None)
            .call("device_join", zero)
            .await
            .is_err()
    );
    let body = join_body(&service, &wallet, "alpha", &mut device, salt).await;
    let joined: crate::api::DeviceJoined = serde_json::from_value(
        client(&service, HOST, None)
            .call("device_join", body)
            .await
            .unwrap(),
    )
    .unwrap();
    let session = open_session(&service, &joined.user, &mut device)
        .await
        .unwrap();
    let member = client(&service, HOST, Some(&session.token));
    // The device-key session reads the commitment it joined with; no publication yet.
    let read: crate::api::InitialCreationResponse =
        serde_json::from_value(member.call("initial_creation", json!({})).await.unwrap()).unwrap();
    assert_eq!(read.seed, SEED);
    assert_eq!(read.publication, None);
    // The genesis evidence: the receipt and the presented lineage_genesis slot.
    let evidence = |salt: [u8; 32], at: u64| {
        cchr::GenesisStampEvidence::new(
            device.receipt.clone(),
            &wallet
                .holder
                .present_stamp(&mut cpsd::rand::rngs::OsRng, &scope, &genesis, NOW)
                .unwrap(),
            salt,
            at,
        )
        .to_bytes()
        .unwrap()
    };
    let good = evidence(genesis_salt, NOW);
    let bind = |seed: [u8; 32], publication: u8, evidence: Option<&Vec<u8>>| match evidence {
        Some(evidence) => {
            json!({"seed": seed, "publication": vec![publication; 32], "evidence": evidence})
        }
        None => json!({"seed": seed, "publication": vec![publication; 32]}),
    };
    // A device-key session binds only with genesis evidence: none, garbage, another salt or
    // another receipt time are refused, and nothing is bound.
    for refused in [
        bind(SEED, 55, None),
        bind(SEED, 55, Some(&vec![1, 2, 3])),
        bind(SEED, 55, Some(&evidence([13; 32], NOW))),
        bind(SEED, 55, Some(&evidence(genesis_salt, NOW - 1))),
    ] {
        assert!(
            member
                .call("initial_publication_bind", refused)
                .await
                .is_err()
        );
    }
    // Only the join's digest is recorded so far.
    assert_eq!(stamp_uses(&service).await, 1);
    // A bind the membership refuses (another seed) frees the recorded genesis digest again.
    assert!(
        member
            .call("initial_publication_bind", bind([34; 32], 55, Some(&good)))
            .await
            .is_err()
    );
    let read: crate::api::InitialCreationResponse =
        serde_json::from_value(member.call("initial_creation", json!({})).await.unwrap()).unwrap();
    assert_eq!(read.publication, None);
    assert_eq!(stamp_uses(&service).await, 1);
    // One publication binds with the evidence; an equal retry agrees (also without
    // re-verification), a retry without evidence, a different winner or seed is refused.
    let bound: crate::api::InitialCreationResponse = serde_json::from_value(
        member
            .call("initial_publication_bind", bind(SEED, 55, Some(&good)))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(bound.publication, Some([55; 32]));
    // The genesis stamp digest is recorded once, beside the join's.
    assert_eq!(stamp_uses(&service).await, 2);
    member
        .call("initial_publication_bind", bind(SEED, 55, Some(&good)))
        .await
        .unwrap();
    assert_eq!(stamp_uses(&service).await, 2);
    for refused in [
        bind(SEED, 55, None),
        bind(SEED, 56, Some(&good)),
        bind([34; 32], 55, Some(&good)),
    ] {
        assert!(
            member
                .call("initial_publication_bind", refused)
                .await
                .is_err()
        );
    }
    let read: crate::api::InitialCreationResponse =
        serde_json::from_value(member.call("initial_creation", json!({})).await.unwrap()).unwrap();
    assert_eq!((read.seed, read.publication), (SEED, Some([55; 32])));
    // The device keys observation names the joined key as the member's credential.
    let keys = member.call("device_keys", json!({})).await.unwrap();
    assert_eq!(keys["keys"], json!([key]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_genesis_stamp_only_re_confirms_the_same_recorded_pending_genesis() {
    let global = configured_wallet(100).await;
    let mut wallet = wallet(&global, 65).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    // Four pending days: the member's registration deadline lies past the stamp's expiry
    // (the end of the cohort after issuance).
    let service = community_with("alpha", &public, |config| config.pending_days = 4).await;
    let pseudonym = wallet
        .holder
        .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
        .to_hex();
    let mut device = keys_device("alpha", &pseudonym).await;
    let key = device.key();
    let salt = [21; 32];
    let scope = community_scope(&service, "alpha").await;
    let genesis_salt = [22; 32];
    let genesis = cchr::lineage_genesis_action(&device.receipt, genesis_salt, NOW).unwrap();
    // ONE stamp, three slots: the join and two candidate geneses (salts 22 and 23).
    let other_salt = [23; 32];
    let other = cchr::lineage_genesis_action(&device.receipt, other_salt, NOW).unwrap();
    stamp(
        &global,
        &mut wallet,
        &[
            (scope.clone(), join_action(&key, salt)),
            (scope.clone(), genesis.clone()),
            (scope.clone(), other.clone()),
        ],
    )
    .await;
    let body = join_body(&service, &wallet, "alpha", &mut device, salt).await;
    let joined: crate::api::DeviceJoined = serde_json::from_value(
        client(&service, HOST, None)
            .call("device_join", body)
            .await
            .unwrap(),
    )
    .unwrap();
    // The client presents the genesis stamp at the genesis time, so the evidence is the same
    // before and after the stamp's cohort ended.
    let evidence = |action: &cpsd::StampAction, salt: [u8; 32]| {
        cchr::GenesisStampEvidence::new(
            device.receipt.clone(),
            &wallet
                .holder
                .present_stamp(&mut cpsd::rand::rngs::OsRng, &scope, action, NOW)
                .unwrap(),
            salt,
            NOW,
        )
        .to_bytes()
        .unwrap()
    };
    let (good, fresh) = (
        evidence(&genesis, genesis_salt),
        evidence(&other, other_salt),
    );
    let pending = |evidence: &Vec<u8>| crate::api::InitialPublicationBind {
        seed: SEED,
        publication: [57; 32],
        evidence: Some(evidence.clone()),
        nonce: None,
    };
    // Before the stamp expired: both geneses verify. The first one's digest is recorded but
    // its bind's outcome stays unknown (record kept, nothing bound): a pending genesis. The
    // second one's record is released again (its bind definitively not applied).
    let early = open_session(&service, &joined.user, &mut device)
        .await
        .unwrap();
    {
        let backend = service.door.community_backend().unwrap().lock().await;
        let (_, authentication) = backend
            .authenticate_current(&early.token, NOW)
            .await
            .unwrap();
        let expires = (NOW + 300) as i64;
        let recorded = backend
            .device_genesis_stamp(&authentication, &pending(&good), expires, NOW)
            .await
            .unwrap();
        assert!(recorded.is_some());
        backend
            .device_genesis_stamp(&authentication, &pending(&fresh), expires, NOW)
            .await
            .unwrap()
            .unwrap()
            .release(NOW)
            .await;
    }
    assert_eq!(stamp_uses(&service).await, 2);

    // Past the stamp's expiry, before the member's registration deadline.
    let late = (NOW / DEFAULT_STAMP_COHORT_SECONDS + 3) * DEFAULT_STAMP_COHORT_SECONDS;
    service.clock.set(late);
    // The community holds the global wallet's current signed status (as it does live).
    global.clock.set(late);
    global.door.maintain().await.unwrap();
    let current: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    std::fs::write(service.dir.path().join("global-status"), &current.status).unwrap();
    std::fs::write(service.dir.path().join("global-ring"), &current.key_ring).unwrap();
    let session = open_session(&service, &joined.user, &mut device)
        .await
        .unwrap();
    let member = client(&service, HOST, Some(&session.token));
    let bind = |evidence: &Vec<u8>| json!({"seed": SEED, "publication": vec![57u8; 32], "evidence": evidence});
    // A NEW genesis with the expired stamp is refused: nothing recorded, nothing bound. The
    // join's record is pruned with its stamp; only the retained pending genesis is left.
    assert!(
        member
            .call("initial_publication_bind", bind(&fresh))
            .await
            .is_err()
    );
    assert_eq!(stamp_uses(&service).await, 1);
    let read: crate::api::InitialCreationResponse =
        serde_json::from_value(member.call("initial_creation", json!({})).await.unwrap()).unwrap();
    assert_eq!(read.publication, None);
    // The same recorded pending genesis (same digest) re-confirms idempotently and binds,
    // without a second record.
    let bound: crate::api::InitialCreationResponse = serde_json::from_value(
        member
            .call("initial_publication_bind", bind(&good))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(bound.publication, Some([57; 32]));
    assert_eq!(stamp_uses(&service).await, 1);
}

/// The ONE pairing stamp action of `community` for the wallet's pseudonym there.
fn pair_action(
    wallet: &Wallet,
    community: &str,
    key: &[u8; 32],
    session: &[u8; 32],
    revision: Option<&[u8; 32]>,
    salt: [u8; 32],
) -> cpsd::StampAction {
    let member = wallet
        .holder
        .pseudonym(&cpsd::CommunityId::new(community).unwrap())
        .to_hex();
    cpsd::StampAction::new(
        cpsd::ActionKind::new(PAIR_ACTION).unwrap(),
        cpsd::PayloadDigest::from_bytes(pair_payload(community, &member, key, session, revision)),
        cpsd::StampSalt::from_bytes(salt),
    )
}

/// A passport presentation over a fresh challenge of `service` at time `now`: the challenge
/// id, the request's `passport` member and the founding document of the trust feed.
async fn pairing_passport(
    service: &Running,
    wallet: &Wallet,
    community: &str,
    now: u64,
) -> (String, Value, Option<Vec<u8>>) {
    let challenge: PresentationChallenge = serde_json::from_value(
        client(service, &host(community), None)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let feed: TrustFeed = serde_json::from_value(
        client(service, &host(community), None)
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
            now,
        )
        .unwrap();
    (
        challenge.challenge.clone(),
        json!({"challenge": challenge.challenge, "proof": proof.to_bytes()}),
        feed.genesis,
    )
}

/// A `device_add` body: the community's one pairing stamp slot, presented by the wallet.
async fn add_body(
    service: &Running,
    wallet: &Wallet,
    community: &str,
    device: &mut impl Device,
    pairing: (&[u8; 32], Option<&[u8; 32]>, [u8; 32]),
    now: u64,
) -> Value {
    let (session, revision, salt) = pairing;
    let (id, passport, genesis) = pairing_passport(service, wallet, community, now).await;
    let key = device.key();
    let stamp = wallet
        .holder
        .present_stamp(
            &mut cpsd::rand::rngs::OsRng,
            &scope_of(community, genesis.as_deref()),
            &pair_action(wallet, community, &key, session, revision, salt),
            now,
        )
        .unwrap()
        .to_bytes();
    json!({
        "passport": passport,
        "stamp": stamp,
        "salt": salt,
        "device_key": key,
        "session": session,
        "revision": revision,
        "signature": device.sign(&pairing_message(ADD_ACTION, community, &id, &key)).await,
    })
}

/// A `device_activate` body: no stamp, only the passport and the key's possession signature.
async fn activate_body(
    service: &Running,
    wallet: &Wallet,
    community: &str,
    device: &mut impl Device,
    now: u64,
) -> Value {
    let (id, passport, _) = pairing_passport(service, wallet, community, now).await;
    let key = device.key();
    json!({
        "passport": passport,
        "device_key": key,
        "signature": device.sign(&pairing_message(ACTIVATE_ACTION, community, &id, &key)).await,
    })
}

/// The registry state of a device key in `community` (`None` when the key is unknown).
async fn registry_state(service: &Running, community: &str, key: &[u8; 32]) -> Option<String> {
    let backend = service.door.community_backend().unwrap().lock().await;
    let mut tx = backend.db.community(community).unwrap().tx().await.unwrap();
    let rows = tx
        .query(
            "SELECT state FROM cvld_device_registry WHERE device_key = ?1",
            crlt::params![key.to_vec()],
        )
        .await
        .unwrap();
    let state = rows.first().map(|row| row.get_str(0).unwrap().to_owned());
    tx.rollback().await.unwrap();
    state
}

/// Another member joins `community` of `service` with its own wallet and first device key.
async fn join_member(
    service: &Running,
    global: &Running,
    wallet: &mut Wallet,
    community: &str,
    device: &mut SigningKey,
) {
    let salt = [19; 32];
    let scope = community_scope(service, community).await;
    stamp(global, wallet, &[(scope, join_action(&device.key(), salt))]).await;
    let body = join_body(service, wallet, community, device, salt).await;
    client(service, &host(community), None)
        .call("device_join", body)
        .await
        .unwrap();
}

#[test]
fn the_pairing_payload_commits_to_every_input() {
    let base = pair_payload("alpha", "m", &[1; 32], &[2; 32], Some(&[3; 32]));
    for other in [
        pair_payload("beta", "m", &[1; 32], &[2; 32], Some(&[3; 32])),
        pair_payload("alpha", "n", &[1; 32], &[2; 32], Some(&[3; 32])),
        pair_payload("alpha", "m", &[4; 32], &[2; 32], Some(&[3; 32])),
        pair_payload("alpha", "m", &[1; 32], &[4; 32], Some(&[3; 32])),
        pair_payload("alpha", "m", &[1; 32], &[2; 32], Some(&[4; 32])),
        pair_payload("alpha", "m", &[1; 32], &[2; 32], None),
    ] {
        assert_ne!(base, other);
    }
    // The length prefixes keep the community and the pseudonym apart.
    assert_ne!(
        pair_payload("ab", "c", &[1; 32], &[2; 32], None),
        pair_payload("a", "bc", &[1; 32], &[2; 32], None)
    );
    assert_ne!(base, join_payload(&[1; 32], &[2; 32]));
}

/// Wallet, service and one joined member whose first key `first` is ACTIVE; one confirmation
/// covered the join and the pairing slots of `pairs`.
struct Paired {
    global: Running,
    wallet: Wallet,
    service: Running,
    joined: crate::api::DeviceJoined,
}

/// One pairing slot: the new key, its community's pairing session, the planned revision, the salt.
type PairSlot = (SigningKey, [u8; 32], Option<[u8; 32]>, [u8; 32]);

/// The shared setup of the pairing tests: join `first`, with ONE confirmation that also covers
/// the one pairing slot of every `(key, session, revision, salt)` in `pairs`.
async fn paired_member(first: &mut SigningKey, pairs: &[PairSlot]) -> Paired {
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
    let scope = community_scope(&service, "alpha").await;
    let join_salt = [9; 32];
    let mut actions = vec![(scope.clone(), join_action(&first.key(), join_salt))];
    for (key, session, revision, salt) in pairs {
        actions.push((
            scope.clone(),
            pair_action(
                &wallet,
                "alpha",
                &key.key(),
                session,
                revision.as_ref(),
                *salt,
            ),
        ));
    }
    stamp(&global, &mut wallet, &actions).await;
    let body = join_body(&service, &wallet, "alpha", first, join_salt).await;
    let joined: crate::api::DeviceJoined = serde_json::from_value(
        client(&service, HOST, None)
            .call("device_join", body)
            .await
            .unwrap(),
    )
    .unwrap();
    Paired {
        global,
        wallet,
        service,
        joined,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_pairing_stamp_registers_the_key_pending_and_activation_needs_no_stamp() {
    let mut first = SigningKey::from_bytes(&[71; 32]);
    let mut second = SigningKey::from_bytes(&[74; 32]);
    let second_key = second.verifying_key().to_bytes();
    let (session, revision, salt) = ([5; 32], Some([6; 32]), [10; 32]);
    let paired = paired_member(&mut first, &[(second.clone(), session, revision, salt)]).await;
    let Paired {
        wallet,
        service,
        joined,
        ..
    } = &paired;
    let anonymous = client(service, HOST, None);
    let pairing = (&session, revision.as_ref(), salt);
    // The proof of possession is the pairing message of THIS step: a join signature or the
    // activate step's signature over the same challenge is refused for `device_add`.
    for wrong in [JOIN_ACTION, ACTIVATE_ACTION] {
        let mut body = add_body(service, wallet, "alpha", &mut second, pairing, NOW).await;
        let challenge = body["passport"]["challenge"].as_str().unwrap().to_owned();
        let message = if wrong == JOIN_ACTION {
            join_message("alpha", &challenge, &second_key)
        } else {
            pairing_message(wrong, "alpha", &challenge, &second_key)
        };
        body["signature"] = json!(second.sign(&message).await);
        assert!(anonymous.call("device_add", body).await.is_err());
    }
    // Activation before the add is refused: no approved PENDING record exists yet.
    let early = activate_body(service, wallet, "alpha", &mut second, NOW).await;
    assert!(anonymous.call("device_activate", early).await.is_err());
    assert_eq!(registry_state(service, "alpha", &second_key).await, None);
    // The stamp covers exactly its salt, key, session and revision; any change is refused.
    let mut wrong_salt = add_body(service, wallet, "alpha", &mut second, pairing, NOW).await;
    wrong_salt["salt"] = json!(vec![11u8; 32]);
    assert!(anonymous.call("device_add", wrong_salt).await.is_err());
    let mut other_key = add_body(service, wallet, "alpha", &mut second, pairing, NOW).await;
    other_key["device_key"] = json!(first.key());
    assert!(anonymous.call("device_add", other_key).await.is_err());
    let mut other_session = add_body(service, wallet, "alpha", &mut second, pairing, NOW).await;
    other_session["session"] = json!(vec![7u8; 32]);
    assert!(anonymous.call("device_add", other_session).await.is_err());
    let mut other_revision = add_body(service, wallet, "alpha", &mut second, pairing, NOW).await;
    other_revision["revision"] = json!(vec![8u8; 32]);
    assert!(anonymous.call("device_add", other_revision).await.is_err());
    let mut no_revision = add_body(service, wallet, "alpha", &mut second, pairing, NOW).await;
    no_revision["revision"] = json!(null);
    assert!(anonymous.call("device_add", no_revision).await.is_err());
    assert_eq!(registry_state(service, "alpha", &second_key).await, None);
    // Add: PENDING grants nothing, and a retry of the same stamp is idempotent while it lives.
    let add = add_body(service, wallet, "alpha", &mut second, pairing, NOW).await;
    anonymous.call("device_add", add).await.unwrap();
    let again = add_body(service, wallet, "alpha", &mut second, pairing, NOW).await;
    anonymous.call("device_add", again).await.unwrap();
    assert_eq!(
        registry_state(service, "alpha", &second_key)
            .await
            .as_deref(),
        Some("pending")
    );
    assert!(
        open_session(service, &joined.user, &mut second)
            .await
            .is_err()
    );
    // The add step's signature does not activate the registered key.
    let mut wrong_step = activate_body(service, wallet, "alpha", &mut second, NOW).await;
    let challenge = wrong_step["passport"]["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    wrong_step["signature"] = json!(
        second
            .sign(&pairing_message(
                ADD_ACTION,
                "alpha",
                &challenge,
                &second_key
            ))
            .await
    );
    assert!(anonymous.call("device_activate", wrong_step).await.is_err());
    // Activation takes no stamp: a stamp (or any other field) in the body is refused.
    let mut stamped = activate_body(service, wallet, "alpha", &mut second, NOW).await;
    stamped["stamp"] = json!(Vec::<u8>::new());
    assert!(anonymous.call("device_activate", stamped).await.is_err());
    // Activate: the key now opens a full member session; the first key still does.
    let activate = activate_body(service, wallet, "alpha", &mut second, NOW).await;
    anonymous
        .call("device_activate", activate.clone())
        .await
        .unwrap();
    assert_eq!(
        registry_state(service, "alpha", &second_key)
            .await
            .as_deref(),
        Some("active")
    );
    let opened = open_session(service, &joined.user, &mut second)
        .await
        .unwrap();
    assert_eq!(opened.user, joined.user);
    open_session(service, &joined.user, &mut first)
        .await
        .unwrap();
    // Replay: the same activation request again fails at its consumed challenge, a fresh
    // activation of the active key stays idempotent, and the add stamp cannot register or
    // reset an active key.
    assert!(anonymous.call("device_activate", activate).await.is_err());
    let fresh = activate_body(service, wallet, "alpha", &mut second, NOW).await;
    anonymous.call("device_activate", fresh).await.unwrap();
    let replayed_add = add_body(service, wallet, "alpha", &mut second, pairing, NOW).await;
    assert!(anonymous.call("device_add", replayed_add).await.is_err());
    assert_eq!(
        registry_state(service, "alpha", &second_key)
            .await
            .as_deref(),
        Some("active")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_needs_the_approved_pending_key_of_the_same_community_member_and_key() {
    let mut first = SigningKey::from_bytes(&[71; 32]);
    let mut second = SigningKey::from_bytes(&[74; 32]);
    let mut stranger = SigningKey::from_bytes(&[75; 32]);
    let second_key = second.verifying_key().to_bytes();
    let (session, salt) = ([5; 32], [10; 32]);
    let paired = paired_member(&mut first, &[(second.clone(), session, None, salt)]).await;
    let Paired {
        global,
        wallet: member,
        service,
        ..
    } = &paired;
    let anonymous = client(service, HOST, None);
    anonymous
        .call(
            "device_add",
            add_body(
                service,
                member,
                "alpha",
                &mut second,
                (&session, None, salt),
                NOW,
            )
            .await,
        )
        .await
        .unwrap();
    // A key that was never approved cannot activate itself, though it holds its own signature.
    let never = activate_body(service, member, "alpha", &mut stranger, NOW).await;
    assert!(anonymous.call("device_activate", never).await.is_err());
    assert_eq!(
        registry_state(service, "alpha", &stranger.key()).await,
        None
    );
    // A different pseudonym cannot activate this member's PENDING key: another member joins
    // the same community and presents the pending key with a valid possession signature.
    let mut other = wallet(global, 62).await;
    let mut other_first = SigningKey::from_bytes(&[76; 32]);
    join_member(service, global, &mut other, "alpha", &mut other_first).await;
    let foreign = activate_body(service, &other, "alpha", &mut second, NOW).await;
    assert!(anonymous.call("device_activate", foreign).await.is_err());
    // Another community holds no approval of this key either: a member of `beta` presents it.
    let public: GlobalPublic = serde_json::from_value(
        client(global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let beta = community("beta", &public).await;
    let mut beta_wallet = wallet(global, 63).await;
    let mut beta_first = SigningKey::from_bytes(&[77; 32]);
    join_member(&beta, global, &mut beta_wallet, "beta", &mut beta_first).await;
    let elsewhere = activate_body(&beta, &beta_wallet, "beta", &mut second, NOW).await;
    assert!(
        client(&beta, &host("beta"), None)
            .call("device_activate", elsewhere)
            .await
            .is_err()
    );
    assert_eq!(registry_state(&beta, "beta", &second_key).await, None);
    // None of this disturbed the approval: the member's own activation still succeeds.
    assert_eq!(
        registry_state(service, "alpha", &second_key)
            .await
            .as_deref(),
        Some("pending")
    );
    let own = activate_body(service, member, "alpha", &mut second, NOW).await;
    anonymous.call("device_activate", own).await.unwrap();
    assert_eq!(
        registry_state(service, "alpha", &second_key)
            .await
            .as_deref(),
        Some("active")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_key_expires_after_the_constant_and_is_removed() {
    let (mut first, mut late, mut early) = (
        SigningKey::from_bytes(&[71; 32]),
        SigningKey::from_bytes(&[74; 32]),
        SigningKey::from_bytes(&[75; 32]),
    );
    let (late_key, early_key) = (late.key(), early.key());
    let (session, salt_late, salt_early, salt_again) = ([5; 32], [10; 32], [11; 32], [12; 32]);
    let paired = paired_member(
        &mut first,
        &[
            (late.clone(), session, None, salt_late),
            (early.clone(), session, None, salt_early),
            (late.clone(), [6; 32], None, salt_again),
        ],
    )
    .await;
    let Paired {
        wallet, service, ..
    } = &paired;
    let anonymous = client(service, HOST, None);
    for (device, salt) in [(&mut late, salt_late), (&mut early, salt_early)] {
        let add = add_body(
            service,
            wallet,
            "alpha",
            device,
            (&session, None, salt),
            NOW,
        )
        .await;
        anonymous.call("device_add", add).await.unwrap();
    }
    let lifetime = PAIRING_PENDING_SECONDS as u64;
    // Still alive one second before the expiry instant: this key activates.
    service.clock.set(NOW + lifetime - 1);
    let alive = activate_body(service, wallet, "alpha", &mut early, NOW + lifetime - 1).await;
    anonymous.call("device_activate", alive).await.unwrap();
    assert_eq!(
        registry_state(service, "alpha", &early_key)
            .await
            .as_deref(),
        Some("active")
    );
    // At the expiry instant the other key is refused AND removed.
    service.clock.set(NOW + lifetime);
    let expired = activate_body(service, wallet, "alpha", &mut late, NOW + lifetime).await;
    assert!(anonymous.call("device_activate", expired).await.is_err());
    assert_eq!(registry_state(service, "alpha", &late_key).await, None);
    // A removed key is unknown: activation stays refused, and only a new approval registers
    // it again (a new add with a fresh stamp), which then lives its own full lifetime.
    let still = activate_body(service, wallet, "alpha", &mut late, NOW + lifetime).await;
    assert!(anonymous.call("device_activate", still).await.is_err());
    let again = add_body(
        service,
        wallet,
        "alpha",
        &mut late,
        (&[6; 32], None, salt_again),
        NOW + lifetime,
    )
    .await;
    anonymous.call("device_add", again).await.unwrap();
    assert_eq!(
        registry_state(service, "alpha", &late_key).await.as_deref(),
        Some("pending")
    );
    let revived = activate_body(service, wallet, "alpha", &mut late, NOW + lifetime).await;
    anonymous.call("device_activate", revived).await.unwrap();
    assert_eq!(
        registry_state(service, "alpha", &late_key).await.as_deref(),
        Some("active")
    );
}

/// One stamp request of `wallet` over a fresh stamp challenge.
async fn stamp_request(
    global: &Running,
    wallet: &mut Wallet,
    key_seed: u8,
) -> (
    Value,
    crate::api::StampChallenge,
    cpsd::StampIssuanceRequest,
    cpsd::IssuanceChallenge,
) {
    let client = client(global, WALLET, Some(&wallet.member.session));
    let reserved: crate::api::StampChallenge =
        serde_json::from_value(client.call("stamp_challenge", json!({})).await.unwrap()).unwrap();
    let challenge =
        cpsd::IssuanceChallenge::from_bytes(reserved.challenge.clone().try_into().unwrap());
    let key = cpsd::StampPublicKey::from_bytes(&reserved.key).unwrap();
    let request = wallet
        .holder
        .begin_stamp(
            &mut cpsd::rand::rngs::OsRng,
            &key,
            &challenge,
            &[(scope("alpha"), join_action(&[key_seed; 32], [key_seed; 32]))],
            NOW,
        )
        .unwrap();
    let body = json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes()});
    (body, reserved, request, challenge)
}

/// C5: the registration's own session issues the account's first stamp with no assertion;
/// the same request again is the same stamp, any later assertion-free request is refused, and
/// the normal confirmed path keeps working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_birth_session_issues_the_first_stamp_without_an_assertion_once() {
    let global = configured_wallet(100).await;
    let (mut member, birth) = enrol_registered(&global, WALLET, None).await;
    member.session = birth.expect("the wallet registration returns its birth session");
    let mut wallet = wallet_of(&global, member, 64).await;
    let client = client(&global, WALLET, Some(&wallet.member.session));
    let (body, _, _, _) = stamp_request(&global, &mut wallet, 7).await;
    let issued = client.call("stamp_issue", body.clone()).await.unwrap();
    assert_eq!(client.call("stamp_issue", body).await.unwrap(), issued);
    let blind: Bytes = serde_json::from_value(issued).unwrap();
    // The device expects the epoch of the signed global status, not one from the reply.
    let public: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let epoch = cchr::global_stamp_trust(&public.key_ring, &public.status, NOW)
        .unwrap()
        .epoch()
        .unwrap();
    wallet
        .holder
        .finish_stamp(
            &cpsd::BlindStamp::from_bytes(&blind.bytes).unwrap(),
            epoch,
            NOW,
        )
        .unwrap();
    // The birth item is closed: another assertion-free request is refused...
    let (body, reserved, request, challenge) = stamp_request(&global, &mut wallet, 8).await;
    assert!(client.call("stamp_issue", body).await.is_err());
    // ...while the same request with its user verification is issued normally.
    let assertion = confirm(
        &mut wallet,
        &reserved.options,
        request.confirmation_challenge(&challenge),
    )
    .await;
    client
        .call(
            "stamp_issue",
            json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes(),"assertion":assertion}),
        )
        .await
        .unwrap();
}

/// The review condition at the host: after a normal stamp, no assertion-free stamp, even from
/// a fresh wallet login that otherwise holds the birth grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_a_normal_stamp_no_session_issues_an_assertion_free_stamp() {
    let global = configured_wallet(100).await;
    let mut wallet = wallet(&global, 65).await;
    stamp(
        &global,
        &mut wallet,
        &[(scope("alpha"), join_action(&[9; 32], [9; 32]))],
    )
    .await;
    let client = client(&global, WALLET, Some(&wallet.member.session));
    let (body, _, _, _) = stamp_request(&global, &mut wallet, 10).await;
    assert!(client.call("stamp_issue", body).await.is_err());
}

/// C1, C3 and C4 at the wallet host, end to end over HTTP: a wallet registration that fixed the
/// seed commitment `c` returns the birth session; that session binds the device key K by K's
/// own signature over (origin, account, credential, c, K), obtains the wallet-signed birth
/// statement for K's genesis receipt, and binds the first wallet publication with that birth
/// evidence. Malformed evidence and evidence for another seed commitment are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_birth_session_binds_the_device_and_the_publication_with_birth_evidence() {
    use crate::api::{
        BirthStatement, Ceremony, InitialCeremony, InitialCreationResponse, Registered,
    };
    use crate::test_support::resident::{Resident, strip_prf};
    let global = configured_wallet(100).await;
    let api = client(&global, WALLET, None);
    let seed = [31u8; 32];
    let begin: Ceremony =
        serde_json::from_value(api.call("register_begin", json!({})).await.unwrap()).unwrap();
    let initial: InitialCeremony = serde_json::from_value(
        api.call(
            "global_initial_registration_continue",
            json!({"ceremony":begin.ceremony,"seed":seed.to_vec()}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let mut device = Resident::default();
    let mut credential = device
        .ceremony(initial.options, true, &origin_for(WALLET))
        .await;
    strip_prf(&mut credential);
    let registered: Registered = serde_json::from_value(
        api.call(
            "wallet_register_finish",
            json!({"ceremony":initial.ceremony,"credential":credential}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let session = registered
        .session
        .expect("the wallet registration returns its birth session");
    let user = registered.user;
    let wallet = client(&global, WALLET, Some(&session.token));
    let passkeys = wallet.call("passkey_list", json!({})).await.unwrap();
    let credential: Vec<u8> =
        serde_json::from_value(passkeys["passkeys"][0]["credential"].clone()).unwrap();
    let keys = keys_device("wallet", &user).await;
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[27; 32]).unwrap();
    let payload = ckmg::wallet_birth_device_payload(
        &origin_for(WALLET),
        &user,
        &credential,
        &seed,
        &keys.key,
    )
    .unwrap();
    let signature = ckmg::passkey::sign_device_birth(
        &prf,
        "wallet",
        ckmg::DeviceFormat::WalletBirthDevice,
        &payload,
    )
    .unwrap();
    wallet
        .call(
            "wallet_device_authorize",
            json!({"key":keys.key,"birth_signature":signature.to_vec()}),
        )
        .await
        .unwrap();
    let statement: BirthStatement = serde_json::from_value(
        wallet
            .call(
                "wallet_birth_genesis",
                json!({"digest":keys.receipt.passkey_challenge().unwrap()}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let evidence =
        cchr::BirthGenesisEvidence::new(keys.receipt.clone(), statement.statement, statement.at)
            .to_bytes()
            .unwrap();
    let bind = |seed: [u8; 32], evidence: &[u8]| json!({"seed":seed.to_vec(),"publication":vec![2u8; 32],"evidence":evidence});
    assert!(
        wallet
            .call("initial_publication_bind", bind(seed, b"not evidence"))
            .await
            .is_err()
    );
    assert!(
        wallet
            .call("initial_publication_bind", bind([32; 32], &evidence))
            .await
            .is_err()
    );
    for _ in 0..2 {
        let state: InitialCreationResponse = serde_json::from_value(
            wallet
                .call("initial_publication_bind", bind(seed, &evidence))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(state.seed, seed);
        assert_eq!(state.publication, Some([2; 32]));
    }
}

#[test]
fn the_pairing_message_is_the_one_the_guest_signs() {
    let key = [5u8; 32];
    for (kind, step) in [
        (ADD_ACTION, ckmg::PairingStep::Add),
        (ACTIVATE_ACTION, ckmg::PairingStep::Activate),
    ] {
        assert_eq!(
            pairing_message(kind, "alpha", "challenge", &key),
            ckmg::PairingPossession::new("alpha", step, "challenge", &key)
                .unwrap()
                .message()
        );
    }
    let add = pairing_message(ADD_ACTION, "alpha", "challenge", &key);
    assert_ne!(
        add,
        pairing_message(ACTIVATE_ACTION, "alpha", "challenge", &key)
    );
    assert_ne!(add, join_message("alpha", "challenge", &key));
    assert_ne!(add, pairing_message("other", "alpha", "challenge", &key));
    assert!(add.starts_with(crate::device_session::POSSESSION_TAG));
}

/// The `delegate` member of a `device_add` body: `host` approves the pairing digest of `key`
/// (the digest the stamp covers) under the PairingApproval format.
async fn delegate_approval(
    wallet: &Wallet,
    host: &mut SigningKey,
    key: &[u8; 32],
    pairing: (&[u8; 32], Option<&[u8; 32]>),
) -> Value {
    let member = wallet
        .holder
        .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
        .to_hex();
    let digest = pair_payload("alpha", &member, key, pairing.0, pairing.1);
    json!({
        "host_key": host.key(),
        "host_signature": host.sign(&approval_message("alpha", &digest)).await,
    })
}

/// The registry's own revocation state for `key` (a lineage revision without it).
async fn revoke_registry_key(service: &Running, key: &[u8; 32]) {
    let backend = service.door.community_backend().unwrap().lock().await;
    let mut tx = backend.db.community("alpha").unwrap().tx().await.unwrap();
    tx.execute(
        "UPDATE cvld_device_registry SET state = 'revoked', pending_until = NULL WHERE device_key = ?1",
        crlt::params![key.to_vec()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn registry_class(service: &Running, key: &[u8; 32]) -> Option<String> {
    let backend = service.door.community_backend().unwrap().lock().await;
    let mut tx = backend.db.community("alpha").unwrap().tx().await.unwrap();
    let rows = tx
        .query(
            "SELECT class FROM cvld_device_registry WHERE device_key = ?1",
            crlt::params![key.to_vec()],
        )
        .await
        .unwrap();
    let class = rows.first().map(|row| row.get_str(0).unwrap().to_owned());
    tx.rollback().await.unwrap();
    class
}

/// A9 (option B, 2026-10-27): a delegated key is a registry row of class `Delegated`, added by
/// the pairing path with an ACTIVE full device's approval; it opens community sessions only,
/// never authorizes another device, and its revocation refuses the very next request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delegated_key_opens_community_sessions_only_until_its_row_is_revoked() {
    let mut first = SigningKey::from_bytes(&[81; 32]);
    let mut delegate = SigningKey::from_bytes(&[84; 32]);
    let mut third = SigningKey::from_bytes(&[85; 32]);
    let delegate_key = delegate.verifying_key().to_bytes();
    let third_key = third.verifying_key().to_bytes();
    let d = ([11; 32], Some([12; 32]), [13; 32]);
    let t = ([14; 32], Some([15; 32]), [16; 32]);
    let paired = paired_member(
        &mut first,
        &[
            (delegate.clone(), d.0, d.1, d.2),
            (third.clone(), t.0, t.1, t.2),
        ],
    )
    .await;
    let mut other = wallet(&paired.global, 66).await;
    let Paired {
        global,
        wallet,
        service,
        joined,
    } = &paired;
    let anonymous = client(service, HOST, None);
    // An unlisted key opens nothing.
    assert!(
        open_session(service, &joined.user, &mut delegate)
            .await
            .is_err()
    );

    // A foreign member's ACTIVE device cannot approve this member's delegate.
    let mut other_first = SigningKey::from_bytes(&[87; 32]);
    join_member(service, global, &mut other, "alpha", &mut other_first).await;
    let mut foreign = add_body(
        service,
        wallet,
        "alpha",
        &mut delegate,
        (&d.0, d.1.as_ref(), d.2),
        NOW,
    )
    .await;
    foreign["delegate"] = delegate_approval(
        wallet,
        &mut other_first,
        &delegate_key,
        (&d.0, d.1.as_ref()),
    )
    .await;
    assert_eq!(
        anonymous.call("device_add", foreign).await.unwrap_err(),
        Error::Refused
    );
    // A host signature over another digest is refused.
    let mut wrong = add_body(
        service,
        wallet,
        "alpha",
        &mut delegate,
        (&d.0, d.1.as_ref(), d.2),
        NOW,
    )
    .await;
    wrong["delegate"] =
        delegate_approval(wallet, &mut first, &delegate_key, (&t.0, t.1.as_ref())).await;
    assert_eq!(
        anonymous.call("device_add", wrong).await.unwrap_err(),
        Error::Refused
    );
    assert_eq!(registry_state(service, "alpha", &delegate_key).await, None);

    // The member's ACTIVE full device approves: PENDING, class delegated, then ACTIVE.
    let mut add = add_body(
        service,
        wallet,
        "alpha",
        &mut delegate,
        (&d.0, d.1.as_ref(), d.2),
        NOW,
    )
    .await;
    add["delegate"] =
        delegate_approval(wallet, &mut first, &delegate_key, (&d.0, d.1.as_ref())).await;
    anonymous.call("device_add", add).await.unwrap();
    assert_eq!(
        registry_class(service, &delegate_key).await.as_deref(),
        Some("delegated")
    );
    let activate = activate_body(service, wallet, "alpha", &mut delegate, NOW).await;
    anonymous.call("device_activate", activate).await.unwrap();
    assert_eq!(
        registry_state(service, "alpha", &delegate_key)
            .await
            .as_deref(),
        Some("active")
    );
    // A listed delegate opens a community session and uses it.
    let session = open_session(service, &joined.user, &mut delegate)
        .await
        .unwrap();
    let member = client(service, HOST, Some(&session.token));
    member.call("lobby", json!({})).await.unwrap();

    // No delegation chains: the delegate cannot approve another device.
    let mut chained = add_body(
        service,
        wallet,
        "alpha",
        &mut third,
        (&t.0, t.1.as_ref(), t.2),
        NOW,
    )
    .await;
    chained["delegate"] =
        delegate_approval(wallet, &mut delegate, &third_key, (&t.0, t.1.as_ref())).await;
    assert_eq!(
        anonymous.call("device_add", chained).await.unwrap_err(),
        Error::Refused
    );
    assert_eq!(registry_state(service, "alpha", &third_key).await, None);

    // An admin session needs the passkey: typed refusal before any stamp is looked at.
    let challenge: DeviceSessionChallenge = serde_json::from_value(
        anonymous
            .call("device_session_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let garden = json!({
        "nonce": challenge.nonce,
        "user": joined.user,
        "device_key": delegate_key,
        "signature": delegate.sign(&garden_message("alpha", &challenge.nonce, challenge.issued)).await,
        "stamp": vec![0u8; 4],
        "salt": vec![0u8; 32],
    });
    assert_eq!(
        client(service, "api.admin.alpha.example.test", None)
            .call("garden_session_finish", garden)
            .await
            .unwrap_err(),
        Error::NeedsPasskey
    );

    // Revocation: the open session's very next request and every new session are refused.
    revoke_registry_key(service, &delegate_key).await;
    assert!(member.call("lobby", json!({})).await.is_err());
    // The revoked delegate is told so, with the distinct reason; nobody else is.
    assert!(matches!(
        open_session(service, &joined.user, &mut delegate).await,
        Err(Error::DelegateRevoked)
    ));

    // A revoked host approves nothing.
    let first_key = first.verifying_key().to_bytes();
    revoke_registry_key(service, &first_key).await;
    let mut revoked = add_body(
        service,
        wallet,
        "alpha",
        &mut third,
        (&t.0, t.1.as_ref(), t.2),
        NOW,
    )
    .await;
    revoked["delegate"] =
        delegate_approval(wallet, &mut first, &third_key, (&t.0, t.1.as_ref())).await;
    assert_eq!(
        anonymous.call("device_add", revoked).await.unwrap_err(),
        Error::Refused
    );
    assert_eq!(registry_state(service, "alpha", &third_key).await, None);
}

/// D1: "needs the passkey" is a typed refusal on the wire (`refused` + reason), which the
/// client decodes back, so a delegated CLI can tell it from any other refusal.
#[test]
fn needs_the_passkey_is_a_typed_refusal_on_the_wire() {
    let wire = serde_json::to_value(crate::error::ErrorBody::from(Error::NeedsPasskey)).unwrap();
    assert_eq!(wire, json!({"error": "refused", "reason": "needs_passkey"}));
    let body: crate::error::ErrorBody = serde_json::from_value(wire).unwrap();
    assert_eq!(body.error(), Some(Error::NeedsPasskey));
    assert_eq!(Error::NeedsPasskey.http_status(), 409);
}

#[test]
fn a_revoked_delegate_is_a_typed_refusal_on_the_wire() {
    let wire = serde_json::to_value(crate::error::ErrorBody::from(Error::DelegateRevoked)).unwrap();
    assert_eq!(
        wire,
        json!({"error": "refused", "reason": "delegate_revoked"})
    );
    let body: crate::error::ErrorBody = serde_json::from_value(wire).unwrap();
    assert_eq!(body.error(), Some(Error::DelegateRevoked));
    // The reason is not valid on any other category.
    let bad: crate::error::ErrorBody =
        serde_json::from_value(json!({"error": "unauthorized", "reason": "delegate_revoked"}))
            .unwrap();
    assert_eq!(bad.error(), None);
}

/// The host approval of a delegated key is exactly the ckmg PairingApproval a full device
/// signs; ckmg lets no delegate sign it.
#[test]
fn the_delegate_approval_is_the_one_a_full_host_device_signs() {
    let digest = pair_payload("alpha", "member", &[5; 32], &[6; 32], Some(&[7; 32]));
    assert_eq!(
        approval_message("alpha", &digest),
        ckmg::PairingApproval::new("alpha", &digest)
            .unwrap()
            .message()
    );
}
