//! Real member/HTTP boundaries; these do not qualify native account acceptance.
#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
mod payment_support;
mod support;
use cmty::cplc;
use cvld::{api::*, service::Door};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::sync::{Arc, atomic::Ordering};
use support::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
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

async fn chunked_status(service: &Running, bearer: &str, action: &str, body: Vec<u8>) -> u16 {
    let address = service.base.strip_prefix("http://").unwrap();
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let headers = format!(
        "POST /v1/{action} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    let send = tokio::spawn(async move {
        writer.write_all(headers.as_bytes()).await?;
        for chunk in body.chunks(1024) {
            writer
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await?;
            writer.write_all(chunk).await?;
            writer.write_all(b"\r\n").await?;
        }
        writer.write_all(b"0\r\n\r\n").await
    });
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reader.take(16 * 1024).read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    // A size refusal may close before the writer finishes the hostile body.
    let _ = send.await.unwrap();
    std::str::from_utf8(&response)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

async fn fixed_length_status(service: &Running, bearer: &str, action: &str, body: Vec<u8>) -> u16 {
    reqwest::Client::new()
        .post(format!("{}/v1/{action}", service.base))
        .header("host", HOST)
        .header("content-type", "application/json")
        .bearer_auth(bearer)
        .body(body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_member_cannot_substitute_for_unconfigured_native_authority_or_body_bounds() {
    let f = routes::fixture().await;
    let api = client(&f.service, HOST, Some(&f.member.session));
    let before = api.call("lobby", json!({})).await.unwrap();
    let proof = presentation(&f.service, HOST, Some(&f.member.session), &f.passport).await;
    let credential = json!({"presentation":proof,"devices":[f.member.signing_key]});
    let valid = json!({"credential":credential,"device":f.member.signing_key});
    assert!(serde_json::from_value::<AccountCredentialRequest>(valid.clone()).is_ok());
    for field in ["scope", "trusted_now", "subject", "checkpoint"] {
        let mut extra = valid.clone();
        extra[field] = json!("caller-selected");
        assert!(serde_json::from_value::<AccountCredentialRequest>(extra).is_err());
    }
    assert_eq!(
        call_status(
            &f.service,
            HOST,
            Some(&f.member.session),
            "account_credential_issue",
            valid
        )
        .await,
        503
    );
    assert_eq!(api.call("lobby", json!({})).await.unwrap(), before);
    for request in [
        json!({"action":"status","clock":NOW}),
        json!({"action":"reset"}),
        json!({"action":"apply","trusted_verifier":true}),
    ] {
        assert_eq!(
            call_status(&f.service, HOST, None, "account", request.clone()).await,
            401
        );
        assert_eq!(
            call_status(
                &f.service,
                HOST,
                Some(&f.member.session),
                "account",
                request
            )
            .await,
            400
        );
    }
    // An unsigned hostile request is syntactically the original owner DTO.
    // There is no installed native authority here to accept its claims.
    let status = json!({
        "action":"status",
        "grant":{"version":3,"issuerKeyId":"unsigned","communityId":"alpha",
            "memberId":"unsigned","pseudonym":"unsigned","chatPublicKey":"unsigned",
            "policyDigest":"unsigned","policyEpoch":1,"passportPolicyDigest":"unsigned",
            "issuedAt":NOW,"expiresAt":NOW+60,"signature":""},
        "authorization":{"version":1,"communityId":"alpha","memberId":"unsigned",
            "rootPublicKey":"unsigned","devicePublicKey":"unsigned",
            "issuedAt":NOW,"expiresAt":NOW+60,"signature":""},
        "request":{"community":SEED,"owner":SEED,"requestId":null,
            "challenge":SEED,"chatPublicKey":"unsigned","issuedAt":NOW,
            "expiresAt":NOW+60,"signature":""},
    });
    assert!(serde_json::from_value::<AccountRequest>(status.clone()).is_ok());
    assert_eq!(
        call_status(
            &f.service,
            HOST,
            Some(&f.member.session),
            "account",
            status.clone()
        )
        .await,
        503
    );
    for (action, request) in [
        (
            "initial_publication_bind",
            json!({"seed":SEED,"publication":PUBLICATION}),
        ),
        (
            "account_credential_issue",
            json!({"credential":credential,"device":f.member.signing_key}),
        ),
        ("account", status),
    ] {
        // Whitespace changes physical size without changing valid DTO fields.
        // Without the cap, the bind would commit and account would return503.
        let mut body = vec![b' '; 256 * 1024];
        body.extend(serde_json::to_vec(&request).unwrap());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            request
        );
        assert_eq!(
            fixed_length_status(&f.service, &f.member.session, action, body.clone()).await,
            400
        );
        assert_eq!(
            chunked_status(&f.service, &f.member.session, action, body,).await,
            400
        );
    }
    let creation: InitialCreationResponse =
        serde_json::from_value(api.call("initial_creation", json!({})).await.unwrap()).unwrap();
    assert_eq!(creation.seed, SEED);
    assert_eq!(creation.publication, None);
    assert_eq!(api.call("lobby", json!({})).await.unwrap(), before);
}

#[test]
fn account_registry_and_owner_wire_refuse_host_authority_fields() {
    for name in ["account", "account_credential_issue"] {
        let registered = action(name).unwrap();
        assert_eq!(registered.access, Access::Member);
        assert_eq!(registered.scope, Scope::Community);
        assert_eq!(registered.effect, Effect::Record);
        assert_eq!(registered.client_access, ClientAccess::Forward);
    }
    for request in [
        json!({"action":"status","clock":NOW}),
        json!({"action":"reset","subject":"caller-selected"}),
        json!({"action":"apply","checkpoint":"caller-selected"}),
    ] {
        assert!(serde_json::from_value::<AccountRequest>(request).is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_rotation_requires_native_owner_and_never_enters_member_registry() {
    let f = routes::fixture().await;
    let api = client(&f.service, HOST, None);
    let before = api.call("trust_feed", json!({})).await.unwrap();
    assert!(matches!(
        f.service
            .door
            .rotate_account_signer(csgn::SecretKey::from_seed(&mut [240; 32]))
            .await,
        Err(cvld::error::Error::Unavailable)
    ));
    assert_eq!(api.call("trust_feed", json!({})).await.unwrap(), before);
    for name in ["rotate_account_signer", "reconcile_account_admission_keys"] {
        assert!(action(name).is_none());
    }
}
