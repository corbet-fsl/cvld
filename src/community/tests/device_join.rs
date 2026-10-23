//! Join by device key with ONE wallet confirmation: the wallet issues a blind stamp after one
//! user verification of its passkey over the exact request; the community binds the member's
//! first device key from a passport presentation plus that stamp, with no community passkey,
//! and the key then opens sessions silently.
use super::*;
use crate::device_session::{
    ACTIVATE_ACTION, ADD_ACTION, JOIN_ACTION, join_message, join_payload, message, pairing_payload,
};
use super::device_session::DEFAULT_STAMP_COHORT_SECONDS;
use crate::test_support::*;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use webauthn_authenticator_rs::AuthenticatorBackend as _;

const HOST: &str = "api.alpha.example.test";

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
/// the device key that signed it, which also joins and opens the member's sessions.
struct KeysDevice {
    keys: ckmg::Keys<KeysStore, KeysClock, ckmg::SystemEntropy, KeysAuthority>,
    key: [u8; 32],
    receipt: ckmg::Receipt,
}
impl Device for KeysDevice {
    fn key(&self) -> [u8; 32] {
        self.key
    }
    async fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        self.keys
            .sign_device_ed25519(message, NOW + 600)
            .await
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
    KeysDevice { keys, key, receipt }
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
        client(service, HOST, None)
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
    wallet
        .holder
        .finish_stamp(&cpsd::BlindStamp::from_bytes(&blind.bytes).unwrap(), NOW)
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
    assert_eq!(client.call("stamp_issue", unverified).await.unwrap(), issued);
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
    let (good, fresh) = (evidence(&genesis, genesis_salt), evidence(&other, other_salt));
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
    let bind = |evidence: &Vec<u8>| {
        json!({"seed": SEED, "publication": vec![57u8; 32], "evidence": evidence})
    };
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

fn pairing_action(kind: &str, key: &[u8; 32], salt: [u8; 32]) -> cpsd::StampAction {
    cpsd::StampAction::new(
        cpsd::ActionKind::new(kind).unwrap(),
        cpsd::PayloadDigest::from_bytes(pairing_payload(kind, key)),
        cpsd::StampSalt::from_bytes(salt),
    )
}

/// A pairing body (`device_add` or `device_activate`) presented with the wallet's stamp.
async fn pairing_body(
    service: &Running,
    wallet: &Wallet,
    kind: &str,
    device: &mut impl Device,
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
        cpsd::CommunityId::new("alpha").unwrap(),
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
    let presentation = wallet
        .holder
        .present_stamp(
            &mut cpsd::rand::rngs::OsRng,
            &scope_of("alpha", feed.genesis.as_deref()),
            &pairing_action(kind, &key, salt),
            NOW,
        )
        .unwrap()
        .to_bytes();
    json!({
        "passport": {"challenge": challenge.challenge, "proof": proof.to_bytes()},
        "stamp": presentation,
        "salt": salt,
        "device_key": key,
        "signature": device.sign(&join_message("alpha", &challenge.challenge, &key)).await,
    })
}

#[test]
fn pairing_payloads_separate_steps_and_keys() {
    let (a, b) = ([1; 32], [2; 32]);
    assert_ne!(
        pairing_payload(ADD_ACTION, &a),
        pairing_payload(ACTIVATE_ACTION, &a)
    );
    assert_ne!(pairing_payload(ADD_ACTION, &a), pairing_payload(ADD_ACTION, &b));
    assert_ne!(pairing_payload(ADD_ACTION, &a), join_payload(&a, &[0; 32]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_further_device_key_is_pending_until_its_activation_stamp() {
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
    let mut first = SigningKey::from_bytes(&[71; 32]);
    let mut second = SigningKey::from_bytes(&[74; 32]);
    let key = first.verifying_key().to_bytes();
    let second_key = second.verifying_key().to_bytes();
    let (join_salt, add_salt, activate_salt) = ([9; 32], [10; 32], [11; 32]);
    let scope = community_scope(&service, "alpha").await;
    // One confirmation covers the join and both pairing steps of the second key.
    stamp(
        &global,
        &mut wallet,
        &[
            (scope.clone(), join_action(&key, join_salt)),
            (scope.clone(), pairing_action(ADD_ACTION, &second_key, add_salt)),
            (
                scope,
                pairing_action(ACTIVATE_ACTION, &second_key, activate_salt),
            ),
        ],
    )
    .await;
    let body = join_body(&service, &wallet, "alpha", &mut first, join_salt).await;
    let joined: crate::api::DeviceJoined = serde_json::from_value(
        client(&service, HOST, None)
            .call("device_join", body)
            .await
            .unwrap(),
    )
    .unwrap();
    let anonymous = client(&service, HOST, None);
    // Activation before registration is refused and does not burn the stamp.
    let early = pairing_body(&service, &wallet, ACTIVATE_ACTION, &mut second, activate_salt).await;
    assert!(anonymous.call("device_activate", early).await.is_err());
    // The add stamp does not approve the activation step, nor another key's add.
    let mut mismatched =
        pairing_body(&service, &wallet, ADD_ACTION, &mut second, add_salt).await;
    mismatched["salt"] = json!(activate_salt);
    assert!(anonymous.call("device_add", mismatched).await.is_err());
    let mut other_key = pairing_body(&service, &wallet, ADD_ACTION, &mut second, add_salt).await;
    other_key["device_key"] = json!(key);
    assert!(anonymous.call("device_add", other_key).await.is_err());
    // Add: PENDING grants nothing, and a retry of the same stamp is idempotent.
    let add = pairing_body(&service, &wallet, ADD_ACTION, &mut second, add_salt).await;
    anonymous.call("device_add", add).await.unwrap();
    let again = pairing_body(&service, &wallet, ADD_ACTION, &mut second, add_salt).await;
    anonymous.call("device_add", again).await.unwrap();
    assert!(open_session(&service, &joined.user, &mut second).await.is_err());
    // Activate: the key now opens a full member session; the first key still does.
    let activate =
        pairing_body(&service, &wallet, ACTIVATE_ACTION, &mut second, activate_salt).await;
    anonymous.call("device_activate", activate).await.unwrap();
    let session = open_session(&service, &joined.user, &mut second)
        .await
        .unwrap();
    assert_eq!(session.user, joined.user);
    open_session(&service, &joined.user, &mut first)
        .await
        .unwrap();
    // A stamp-less pairing request is refused.
    let mut stampless =
        pairing_body(&service, &wallet, ACTIVATE_ACTION, &mut second, activate_salt).await;
    stampless["stamp"] = json!(Vec::<u8>::new());
    assert!(anonymous.call("device_activate", stampless).await.is_err());
}

/// One stamp request of `wallet` over a fresh stamp challenge.
async fn stamp_request(
    global: &Running,
    wallet: &mut Wallet,
    key_seed: u8,
) -> (Value, crate::api::StampChallenge, cpsd::StampIssuanceRequest, cpsd::IssuanceChallenge) {
    let client = client(global, WALLET, Some(&wallet.member.session));
    let reserved: crate::api::StampChallenge =
        serde_json::from_value(client.call("stamp_challenge", json!({})).await.unwrap()).unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(reserved.challenge.clone().try_into().unwrap());
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
    wallet
        .holder
        .finish_stamp(&cpsd::BlindStamp::from_bytes(&blind.bytes).unwrap(), NOW)
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
    stamp(&global, &mut wallet, &[(scope("alpha"), join_action(&[9; 32], [9; 32]))]).await;
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
    let signature = ckmg::passkey::sign_device_opened(
        &prf,
        "wallet",
        ckmg::DevicePurpose::WalletBirthDevice,
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
