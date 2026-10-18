//! Production phone/mailbox and paid access compose through the actual registry.
//! This tests the CVLD boundary through genuine Guard admission, not Forum G2
//! or Tor transport. Only external provider HTTP is inert.
#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
use crate::payment_support;
use crate::support;
use cmty::cplc;
use cvld::{api::*, service::{Clock as _, Door}};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use std::sync::{Arc, atomic::Ordering};
use support::*;

#[path = "production_journey/contacts.rs"]
mod contacts;
#[path = "production_journey/payment.rs"]
mod payment;

const HOST: &str = "api.alpha.example.test";

async fn feed(service: &Running) -> TrustFeed {
    serde_json::from_value(
        client(service, HOST, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap()
}

fn guard(bundle: &cgrd::Bundle, feed: &TrustFeed) -> cgrd::Admission {
    let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    // Independent fictional deployment key, not authority inferred from HTTP.
    assert_eq!(
        ring.keys()[0].public_key(),
        SigningKey::from_bytes(&[b'a'; 32])
            .verifying_key()
            .to_bytes()
    );
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
                expected_issuance_action: cmty::ADMISSION_ACTION,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_production_contacts_passport_paid_membership_and_guard_share_one_journey() {
    let (global, contact_wire, cohort) = contacts::production(true).await;
    let (_wallet, passport, public) = contacts::wallet(&global, cohort).await;
    assert_eq!(contact_wire.calls(), 4);
    let payment_wire = payment_support::Wire::new(payment_support::Reply::Success);
    let service = payment::community_founded(&global, cohort, &public, payment_wire.clone()).await;
    // Founding the community verified the founder's own contacts; admission must add no provider call after that.
    let after_founding = contact_wire.calls();
    let mut member = enrol_community(&service, HOST, &passport).await;
    let api = client(&service, HOST, Some(&member.session));
    api.call("handle_reserve", json!({"handle":"production_member"}))
        .await
        .unwrap();
    // Phone and mailbox alone do not satisfy this caller's paid-access policy.
    let missing = issue_community(&service, HOST, &member, &passport).await;
    assert!(missing.credential.is_none());
    assert_ne!(missing.lobby.state, "admitted");
    assert_eq!(payment_wire.settled.load(Ordering::SeqCst), 0);
    payment::settle(&service, &member).await;
    let issued = issue_community(&service, HOST, &member, &passport).await;
    assert_eq!(issued.lobby.state, "admitted");
    assert_eq!(issued.lobby.handle.as_deref(), Some("production_member"));
    assert_eq!(payment_wire.supported.load(Ordering::SeqCst), 1);
    assert_eq!(payment_wire.verified.load(Ordering::SeqCst), 1);
    assert_eq!(payment_wire.settled.load(Ordering::SeqCst), 1);
    assert_eq!(contact_wire.calls(), after_founding);
    let public = feed(&service).await;
    let credential = issued.credential.unwrap();
    let ring = csgn::KeyRing::from_cbor(&public.key_ring).unwrap();
    let verified = ring
        .verify(&credential, csgn::Kind::Credential, NOW)
        .unwrap();
    let claims: cplc::Credential = serde_json::from_slice(verified.payload()).unwrap();
    assert_eq!(claims.purpose, cplc::CredentialPurpose::CommunityAdmission);
    assert_eq!(claims.issuance_action, cmty::ADMISSION_ACTION);
    assert_eq!(claims.gates.len(), 1);
    assert_eq!(claims.gates[0].gate, "crpt");
    assert_eq!(claims.gates[0].provider, "fixture-facilitator");
    assert_eq!(claims.devices, vec![member.signing_key]);
    let encoded = String::from_utf8(verified.payload().to_vec()).unwrap();
    for raw in [
        "cphn",
        "cmbx",
        "+12025550123",
        "Member+alias",
        "PRIVATE-PAYER",
        "PRIVATE-CHAIN-TRANSACTION",
        "proven_at",
        "holder_secret",
    ] {
        assert!(!encoded.contains(raw));
    }
    let payload = serde_json::to_vec(&cgrd::BundleContent {
        community: "alpha".into(),
        member: claims.member.clone(),
        device: member.signing_key,
        hpke_key: None,
        credential,
        profile: cgrd::Profile::Public(
            serde_json::from_value(json!({
                "community":"alpha", "schema_version":1, "public":{},
            }))
            .unwrap(),
        ),
        openings: Vec::new(),
        vouched_by: None,
        vouched_verified: false,
        vouched_snapshot: None,
    })
    .unwrap();
    let bundle = cgrd::Bundle {
        signature: SigningKey::from_bytes(&[13; 32])
            .sign(&cgrd::binding_bytes(&payload))
            .to_bytes()
            .to_vec(),
        payload,
    };
    assert!(guard(&bundle, &public).is_admitted());
    let certificate: PasskeyCertificateResponse =
        serde_json::from_value(api.call("passkey_certificate", json!({})).await.unwrap()).unwrap();
    assert_eq!(certificate.checked_at, service.clock.now());
    let certified =
        ckyh::certificate::verify(&ring, &certificate.bytes, &claims.member, NOW).unwrap();
    assert_eq!(certified.credential_id(), member.credential.as_slice());
    // Last-key revocation must reach the same signed graph, even though the
    // independent original certificate signature retains its normal lifetime.
    let body = proven(
        &service,
        HOST,
        &member.session,
        &mut member.authenticator,
        json!({"kind":"passkey_revoke","credential":member.credential}),
        json!({"credential":member.credential}),
    )
    .await;
    api.call("passkey_revoke", body).await.unwrap();
    let revoked = feed(&service).await;
    assert!(!guard(&bundle, &revoked).is_admitted());
    assert!(ckyh::certificate::verify(&ring, &certificate.bytes, &claims.member, NOW).is_ok());
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "passkey_certificate",
            json!({})
        )
        .await,
        401
    );
    let proof = presentation(&service, HOST, None, &passport).await;
    assert_eq!(
        call_status(
            &service,
            HOST,
            None,
            "register_begin",
            json!({"passport":proof})
        )
        .await,
        409
    );
    assert_eq!(payment_wire.settled.load(Ordering::SeqCst), 1);
    assert_eq!(contact_wire.calls(), after_founding);
}
