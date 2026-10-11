//! Public input capture for a future genuine native-account fixture.
//! This is not an account checkpoint, grant, proof, or accepted wallet state.
#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
mod payment_support;
mod support;
use cmty::cplc;
use cpsd::rand::{SeedableRng, rngs::StdRng};
use cvld::{api::*, service::Door};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::sync::Arc;
use support::*;

#[path = "production_journey/contacts.rs"]
#[allow(dead_code)]
mod contacts;
#[path = "production_journey/payment.rs"]
#[allow(dead_code)]
mod payment;

const HOST: &str = "api.alpha.example.test";

fn resolved_source(package: &str) -> &str {
    let section = include_str!("../Cargo.lock")
        .split("[[package]]")
        .find(|section| {
            section
                .lines()
                .any(|line| line == format!("name = \"{package}\""))
        })
        .expect("owner is present in the actual resolved lock");
    section
        .lines()
        .find_map(|line| {
            line.strip_prefix("source = \"")
                .and_then(|s| s.strip_suffix('"'))
        })
        .expect("first-party owner has a resolved source")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_public_member_parameters_after_real_production_enrollment() {
    // Fictional deterministic fixture inputs remain in memory. Only owner
    // public encodings are written; no holder/key/passport serialization.
    let holder = cpsd::HolderSecret::generate(&mut StdRng::from_seed([43; 32]));
    let community = cpsd::CommunityId::new("alpha").unwrap();
    let pseudonym = holder.pseudonym(&community);
    let member = pseudonym.to_bytes();
    let account_member = cblc::admission::member_id(&member);
    let issuer = cpsd::IssuerKey::generate(
        &mut StdRng::from_seed([44; 32]),
        cpsd::KeyId::new("production-contact-fixture").unwrap(),
        ["cphn", "cmbx"]
            .map(|gate| cpsd::GateId::new(gate).unwrap())
            .to_vec(),
    )
    .unwrap();
    let (global, wire, cohort) = contacts::production_with_issuer(true, &issuer).await;
    let (_wallet, passport, public) = contacts::wallet_with_holder(&global, cohort, &holder).await;
    assert_eq!(wire.calls(), 4);
    assert_eq!(public.issuer, issuer.public_key().to_bytes());
    let service = payment::community(
        &public,
        payment_support::Wire::new(payment_support::Reply::Success),
    )
    .await;
    let enrolled = enrol_community(&service, HOST, &passport).await;
    let api = client(&service, HOST, Some(&enrolled.session));
    let lobby: Lobby = serde_json::from_value(api.call("lobby", json!({})).await.unwrap()).unwrap();
    assert_eq!(lobby.member_id, pseudonym.to_hex());
    let observed_at = cvld::service::Clock::now(service.clock.as_ref());
    assert_eq!(observed_at, NOW);
    let feed: TrustFeed =
        serde_json::from_value(api.call("trust_feed", json!({})).await.unwrap()).unwrap();
    let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    let actual_policy_key = SigningKey::from_bytes(&[b'a'; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(ring.keys()[0].public_key(), actual_policy_key);
    let manifest = ring
        .verify(&feed.manifest, csgn::Kind::SettingsSnapshot, observed_at)
        .unwrap();
    let manifest: cplc::TrustManifest = serde_json::from_slice(manifest.payload()).unwrap();
    assert_eq!(manifest.policy_epoch, feed.policy_epoch);
    let revision = feed
        .key_transitions
        .last()
        .map_or(0, |value| value.revision);
    let certificate_issuer = cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap();
    let parameters = json!({
        "purpose":"cvld.public-native-account-parameters.v1",
        "provenance":{
            "test":"tests/native_account_parameters.rs",
            "holder_api":"cpsd::HolderSecret::generate(StdRng fixture) -> pseudonym(CommunityId)",
            "member_digest_api":"cblc::admission::member_id",
            "cpsd_source":resolved_source("cpsd"),
            "cblc_source":resolved_source("cblc"),
            "cplc_source":resolved_source("cplc")
        },
        "community":"alpha",
        "observed_at":observed_at,
        "global_cohort":cohort,
        "member":member.to_vec(),
        "membership_subject":lobby.member_id,
        "account_member_id":account_member,
        "passport_issuer":{
            "key_id":"production-contact-fixture",
            "gates":["cphn","cmbx"],
            "public_key":public.issuer
        },
        "actual_policy":{
            "epoch":feed.policy_epoch,
            "key_revision":revision,
            "key_ring":feed.key_ring,
            "key_transitions":feed.key_transitions,
            "public_key":actual_policy_key,
            "manifest":feed.manifest
        },
        "planned_native_admission_trust":{
            "community_id":"alpha",
            "policy_key_revision":revision,
            "policy_public_key":actual_policy_key,
            "immutable_admission_policy_digest":vec![3_u8;32],
            "device_public_key":enrolled.signing_key,
            "operator_public_key":SigningKey::from_bytes(&[9;32]).verifying_key().to_bytes(),
            "certificate_issuer_public_key":certificate_issuer.public_key().to_vec(),
            "requires_independent_configuration_before_activation":true
        },
        "account_checkpoint":null,
        "native_proof":null,
        "qualification":"public parameters and genuine passport enrollment only; no initialized account or G2 claim"
    });
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("native-account-parameters.json"),
        serde_json::to_vec_pretty(&parameters).unwrap(),
    )
    .unwrap();
}
