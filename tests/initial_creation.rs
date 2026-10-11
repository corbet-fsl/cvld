//! Initial enrollment receipts require the actual current original passkey.
#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
mod payment_support;
mod support;
use cmty::cplc;
use cvld::{api::*, service::Door};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::sync::{Arc, atomic::Ordering};
use support::*;
use webauthn_authenticator_rs::{AuthenticatorBackend as _, softtoken::SoftToken};

#[path = "production_journey/contacts.rs"]
mod contacts;
#[allow(dead_code)]
#[path = "production_journey/payment.rs"]
mod payment;
#[path = "initial_creation/routes.rs"]
mod routes;

const HOST: &str = "api.alpha.example.test";
const SEED: [u8; 32] = [17; 32];
const PUBLICATION: [u8; 32] = [29; 32];
const OTHER_SEED: [u8; 32] = [18; 32];
const OTHER_PUBLICATION: [u8; 32] = [30; 32];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_current_key_cannot_substitute_for_the_original_creation_key() {
    let f = routes::fixture().await;
    let api = client(&f.service, HOST, Some(&f.member.session));
    let begin: AddedPasskey = serde_json::from_value(
        api.call("passkey_add", json!({"step":"begin"}))
            .await
            .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Challenge {
        ceremony, options, ..
    } = begin
    else {
        panic!("expected real additional-key ceremony")
    };
    let challenge: ckyh::CreationChallengeResponse = serde_json::from_value(options).unwrap();
    let mut options = challenge.public_key;
    options
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let mut other = SoftToken::new(true).unwrap().0;
    let credential = other
        .perform_register(
            ckyh::Url::parse(&format!("https://{HOST}")).unwrap(),
            options,
            300_000,
        )
        .unwrap();
    let credential_id = credential.raw_id.as_ref().to_vec();
    let added: AddedPasskey = serde_json::from_value(
        api.call(
            "passkey_add",
            json!({"step":"finish","ceremony":ceremony,"credential":credential}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Registered { user, credential } = added else {
        panic!("expected real registered key")
    };
    assert_eq!(user, f.member.user);
    assert_eq!(credential, credential_id);
    let other_session = login(&f.service, HOST, &mut other, &user, &credential_id).await;
    for (action, request) in [
        ("initial_creation", json!({})),
        (
            "initial_publication_bind",
            json!({"seed":SEED,"publication":PUBLICATION}),
        ),
    ] {
        assert_eq!(
            call_status(&f.service, HOST, Some(&other_session), action, request).await,
            409
        );
    }
    let original: InitialCreationResponse =
        serde_json::from_value(api.call("initial_creation", json!({})).await.unwrap()).unwrap();
    assert_eq!(original.seed, SEED);
    assert_eq!(original.publication, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_registration_cannot_acquire_creation_provenance_retroactively() {
    let f = routes::fixture_with(None).await;
    for (action, request) in [
        ("initial_creation", json!({})),
        (
            "initial_publication_bind",
            json!({"seed":SEED,"publication":PUBLICATION}),
        ),
    ] {
        assert_eq!(
            call_status(&f.service, HOST, Some(&f.member.session), action, request).await,
            409
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_creation_is_bound_once_and_receipt_retry_does_not_create_authority() {
    let f = routes::fixture().await;
    let api = client(&f.service, HOST, Some(&f.member.session));
    let initial: InitialCreationResponse =
        serde_json::from_value(api.call("initial_creation", json!({})).await.unwrap()).unwrap();
    assert_eq!(initial.seed, SEED);
    assert_eq!(initial.publication, None);
    assert_eq!(initial.checked_at, NOW);
    let bind = json!({"seed":SEED,"publication":PUBLICATION});
    let first: InitialCreationResponse = serde_json::from_value(
        api.call("initial_publication_bind", bind.clone())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first.seed, SEED);
    assert_eq!(first.publication, Some(PUBLICATION));
    assert_eq!(first.checked_at, NOW);
    let retry: InitialCreationResponse =
        serde_json::from_value(api.call("initial_publication_bind", bind).await.unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(retry).unwrap()
    );
    for bad in [
        json!({"seed":OTHER_SEED,"publication":PUBLICATION}),
        json!({"seed":SEED,"publication":OTHER_PUBLICATION}),
    ] {
        assert_eq!(
            call_status(
                &f.service,
                HOST,
                Some(&f.member.session),
                "initial_publication_bind",
                bad
            )
            .await,
            409
        );
    }
    let current: InitialCreationResponse =
        serde_json::from_value(api.call("initial_creation", json!({})).await.unwrap()).unwrap();
    assert_eq!(current.publication, Some(PUBLICATION));
    let encoded = serde_json::to_value(current).unwrap();
    assert_eq!(encoded.as_object().unwrap().len(), 3);
    for field in [
        "user",
        "member",
        "token",
        "credential",
        "grant",
        "root",
        "secret",
    ] {
        assert!(encoded.get(field).is_none());
    }
    let lobby: Lobby = serde_json::from_value(api.call("lobby", json!({})).await.unwrap()).unwrap();
    assert_ne!(lobby.state, "admitted");
    let proof = presentation(&f.service, HOST, None, &f.passport).await;
    assert_eq!(
        call_status(
            &f.service,
            HOST,
            None,
            "initial_registration_begin",
            json!({"passport":proof,"seed":OTHER_SEED})
        )
        .await,
        409
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_receipts_refuse_foreign_hosts_sessions_and_revoked_keys() {
    let f = routes::fixture().await;
    for action in ["initial_creation", "initial_publication_bind"] {
        let body = if action == "initial_creation" {
            json!({})
        } else {
            json!({"seed":SEED,"publication":PUBLICATION})
        };
        assert_eq!(
            call_status(&f.service, HOST, None, action, body.clone()).await,
            401
        );
        assert_eq!(
            call_status(&f.service, HOST, Some("foreign-session"), action, body).await,
            401
        );
    }
    for host in ["api.root.example.test", "api.admin.alpha.example.test"] {
        let proof = presentation(&f.service, HOST, None, &f.passport).await;
        assert_eq!(
            call_status(
                &f.service,
                host,
                None,
                "initial_registration_begin",
                json!({"passport":proof,"seed":SEED})
            )
            .await,
            421
        );
    }
    let api = client(&f.service, HOST, Some(&f.member.session));
    assert_eq!(
        call_status(
            &f.service,
            HOST,
            Some(&f.member.session),
            "initial_publication_bind",
            json!({"seed":SEED,"publication":PUBLICATION,"user":f.member.user})
        )
        .await,
        400
    );
    api.call("passkey_revoke", json!({"credential":f.member.credential}))
        .await
        .unwrap();
    assert_eq!(
        call_status(
            &f.service,
            HOST,
            Some(&f.member.session),
            "initial_creation",
            json!({})
        )
        .await,
        401
    );
    let proof = presentation(&f.service, HOST, None, &f.passport).await;
    assert_eq!(
        call_status(
            &f.service,
            HOST,
            None,
            "initial_registration_begin",
            json!({"passport":proof,"seed":SEED})
        )
        .await,
        409
    );
}
