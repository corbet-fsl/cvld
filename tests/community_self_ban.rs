//! Genuine resident passkeys, blind passports and signed community publications.
#![cfg(feature = "development-gate")]
mod support;
use cmty::cplc;
use cvld::{api::*, service::Clock};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use support::{
    resident::{Resident, strip_prf},
    *,
};

const HOST: &str = "api.alpha.example.test";
struct Member {
    device: Resident,
    session: Session,
    credential: Vec<u8>,
}
async fn discover(service: &Running, host: &str, device: &mut Resident) -> Session {
    let api = client(service, host, None);
    let challenge: DiscoverableCeremony = serde_json::from_value(
        api.call("login_discoverable_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut credential = device
        .ceremony(challenge.options, false, &support::origin_for(host))
        .await;
    strip_prf(&mut credential);
    serde_json::from_value(
        api.call(
            "login_finish",
            json!({"ceremony":challenge.ceremony,"credential":credential}),
        )
        .await
        .unwrap(),
    )
    .unwrap()
}
async fn member(service: &Running, host: &str, passport: &cpsd::Passport) -> Member {
    let proof = presentation(service, host, None, passport).await;
    let api = client(service, host, None);
    let begin: Ceremony = serde_json::from_value(
        api.call("register_begin", json!({"passport":proof}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut device = Resident::default();
    let mut credential = device
        .ceremony(begin.options, true, &support::origin_for(host))
        .await;
    strip_prf(&mut credential);
    let id: ckyh::RegisterPublicKeyCredential = serde_json::from_value(credential.clone()).unwrap();
    let user: User = serde_json::from_value(
        api.call(
            "register_finish",
            json!({"ceremony":begin.ceremony,"credential":credential}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let session = discover(service, host, &mut device).await;
    assert_eq!(session.user, user.user);
    Member {
        device,
        session,
        credential: id.raw_id.as_ref().to_vec(),
    }
}
async fn challenge(service: &Running, owner: &Member) -> SelfBanChallenge {
    let challenge: SelfBanChallenge = serde_json::from_value(
        client(service, HOST, Some(&owner.session.token))
            .call("community_self_ban_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        challenge.intent,
        SelfBanIntent::PermanentCommunitySelfBan
    ));
    assert!(challenge.warning.contains("permanent"));
    assert!(challenge.warning.contains("no undo"));
    assert_eq!(challenge.expires, service.clock.now() + 300);
    assert_eq!(
        challenge.options["publicKey"]["userVerification"],
        "required"
    );
    challenge
}
async fn answer(owner: &mut Member, challenge: SelfBanChallenge) -> Value {
    let mut credential = owner
        .device
        .ceremony(challenge.options, false, &format!("https://{HOST}"))
        .await;
    strip_prf(&mut credential);
    json!({"ceremony":challenge.ceremony,"credential":credential})
}
async fn feed(service: &Running) -> TrustFeed {
    serde_json::from_value(
        client(service, HOST, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap()
}
fn revocations(feed: &TrustFeed) -> cplc::Revocations {
    cplc::verify_snapshot::<cplc::Revocations>(
        &csgn::KeyRing::from_cbor(&feed.key_ring).unwrap(),
        &feed.revocations,
        cplc::SnapshotExpectation {
            community: "alpha",
            kind: cplc::SnapshotKind::RevocationList,
            minimum_revision: 1,
            policy_epoch: feed.policy_epoch,
            now: NOW,
        },
    )
    .unwrap()
    .content
}

async fn admitted_bundle(
    service: &Running,
    owner: &mut Member,
    passport: &cpsd::Passport,
) -> cgrd::Bundle {
    let api = client(service, HOST, Some(&owner.session.token));
    api.call("handle_reserve", json!({"handle":"member_self_ban"}))
        .await
        .unwrap();
    let lobby: Lobby = serde_json::from_value(api.call("lobby", json!({})).await.unwrap()).unwrap();
    api.voucher_redeem(voucher(
        "alpha",
        &lobby.member_id,
        "self-ban-voucher",
        NOW + 86400,
    ))
    .await
    .unwrap();
    let device_key = SigningKey::from_bytes(&[37; 32]);
    let key = device_key.verifying_key().to_bytes();
    let proof = owner
        .device
        .step_up(
            service,
            HOST,
            &owner.session.token,
            json!({"kind":"device_authorize","key":key}),
        )
        .await;
    api.call("device_authorize", json!({"key":key,"step_up":proof}))
        .await
        .unwrap();
    let proof = presentation(service, HOST, Some(&owner.session.token), passport).await;
    let issued: CredentialResponse = serde_json::from_value(
        api.call(
            "credential_issue",
            json!({"presentation":proof,"devices":[device_key.verifying_key().to_bytes()]}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(issued.lobby.state, "admitted");
    let payload = serde_json::to_vec(&cgrd::BundleContent {
        community: "alpha".into(),
        member: lobby.member_id,
        device: device_key.verifying_key().to_bytes(),
        hpke_key: None,
        credential: issued.credential.unwrap(),
        profile: cgrd::Profile::Public(
            serde_json::from_value(json!({"community":"alpha","schema_version":1,"public":{}}))
                .unwrap(),
        ),
        openings: Vec::new(),
    })
    .unwrap();
    cgrd::Bundle {
        signature: device_key
            .sign(&cgrd::binding_bytes(&payload))
            .to_bytes()
            .to_vec(),
        payload,
    }
}
fn guard(bundle: &cgrd::Bundle, feed: &TrustFeed) -> cgrd::Admission {
    guard_for_action(bundle, feed, cmty::ADMISSION_ACTION)
}
fn guard_for_action(
    bundle: &cgrd::Bundle,
    feed: &TrustFeed,
    expected_action: &str,
) -> cgrd::Admission {
    let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    let manifest = ring
        .verify(&feed.manifest, csgn::Kind::SettingsSnapshot, NOW)
        .unwrap();
    let manifest: cplc::TrustManifest = serde_json::from_slice(manifest.payload()).unwrap();
    assert_eq!(manifest.policy_epoch, feed.policy_epoch);
    cgrd::check_published(
        bundle,
        &cgrd::PublishedPolicy {
            policy: cgrd::Policy {
                community: "alpha",
                expected_issuance_action: expected_action,
                keys: &ring,
                now: NOW,
                minimum_epoch: manifest.policy_epoch,
                minimum_settings_revision: 1,
                minimum_schema_revision: 1,
                maximum_snapshot_age: 86400,
                settings: &feed.settings,
            },
            revocations: &feed.revocations,
            minimum_revocations_revision: 1,
        },
        &feed.schema,
    )
}

#[path = "community_self_ban/authorization.rs"]
mod authorization;
#[path = "community_self_ban/lifecycle.rs"]
mod lifecycle;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_real_issuer_and_guard_share_an_action_verdict_without_exporting_global_gate_facts() {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut owner = member(&service, HOST, &passport).await;
    let bundle = admitted_bundle(&service, &mut owner, &passport).await;
    let feed = feed(&service).await;
    let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    let body: cgrd::BundleContent = serde_json::from_slice(&bundle.payload).unwrap();
    let signed = ring
        .verify(&body.credential, csgn::Kind::Credential, NOW)
        .unwrap();
    let credential: cplc::Credential = serde_json::from_slice(signed.payload()).unwrap();
    assert!(credential.purpose == cplc::CredentialPurpose::CommunityAdmission);
    assert_eq!(credential.issuance_action, cmty::ADMISSION_ACTION);
    assert_eq!(credential.policy_epoch, feed.policy_epoch);
    assert_eq!(credential.gates.len(), 1);
    assert_eq!(credential.gates[0].gate, "cvch");
    assert_eq!(credential.gates[0].provider, "sponsor");
    // The unchanged fixture requires both the global passport and community
    // voucher. The issuer checks both; only its action verdict crosses the
    // privacy boundary. The guard consumes the actual signed output directly.
    assert!(guard(&bundle, &feed).is_admitted());
    assert!(!guard_for_action(&bundle, &feed, "another.action").is_admitted());
}
