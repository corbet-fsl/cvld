//! Real HTTP certificate retrieval through the existing owned community graph.
#![cfg(feature = "development-gate")]
use crate::support;

use cvld::{
    api::*,
    service::{Clock, Door},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use support::*;

const HOST: &str = "api.alpha.example.test";

async fn certificate(service: &Running, member: &Member) -> PasskeyCertificateResponse {
    serde_json::from_value(
        client(service, HOST, Some(&member.session))
            .call("passkey_certificate", json!({}))
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn http_certificate_uses_current_registered_key_and_original_pseudonym_before_admission() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut member = enrol_community(&service, HOST, &passport).await;
    // No credential_issue call or community admission credential is supplied.
    let lobby: Lobby = serde_json::from_value(
        client(&service, HOST, Some(&member.session))
            .call("lobby", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let before: TrustFeed = serde_json::from_value(
        client(&service, HOST, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let bytes = certificate(&service, &member).await;
    assert_eq!(bytes.checked_at, NOW);
    let ring = csgn::KeyRing::from_cbor(&before.key_ring).unwrap();
    let verified = ckyh::certificate::verify(&ring, &bytes.bytes, &lobby.member_id, NOW).unwrap();
    assert_eq!(verified.credential_id(), member.credential);
    assert_eq!(verified.member(), lobby.member_id);
    assert_ne!(verified.member(), member.user);
    let signed = ring
        .verify(&bytes.bytes, csgn::Kind::Credential, NOW)
        .unwrap();
    let body: Value = serde_json::from_slice(signed.payload()).unwrap();
    assert_eq!(body["purpose"], "ckyh.passkey-certificate.v1");
    assert!(
        !String::from_utf8(signed.payload().to_vec())
            .unwrap()
            .contains(&member.user)
    );
    assert!(ckyh::certificate::verify(&ring, &bytes.bytes, "another-member", NOW).is_err());
    let after: TrustFeed = serde_json::from_value(
        client(&service, HOST, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(before.settings, after.settings);
    assert_eq!(before.revocations, after.revocations);

    assert_eq!(
        call_status(&service, HOST, None, "passkey_certificate", json!({})).await,
        401
    );
    assert_eq!(
        call_status(
            &service,
            ROOT,
            Some(&member.session),
            "passkey_certificate",
            json!({})
        )
        .await,
        401
    );
    assert_eq!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "passkey_certificate",
            json!({"credential":member.credential})
        )
        .await,
        400
    );
    let body = proven(
        &service,
        HOST,
        &member.session,
        &mut member.authenticator,
        json!({"kind":"passkey_revoke","credential":member.credential}),
        json!({"credential":member.credential}),
    )
    .await;
    client(&service, HOST, Some(&member.session))
        .call("passkey_revoke", body)
        .await
        .unwrap();
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
    // The old COSE remains signature-valid; current revocation is a separate relation.
    ckyh::certificate::verify(&ring, &bytes.bytes, &lobby.member_id, NOW).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn http_certificate_requires_community_member_role_and_exclusive_session_lifetime() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let member = enrol_community(&service, HOST, &passport).await;
    let root = enrol(&service, ROOT, Some("synthetic-root-enrolment-capability")).await;
    assert_eq!(
        call_status(
            &service,
            ROOT,
            Some(&root.session),
            "passkey_certificate",
            json!({})
        )
        .await,
        403
    );
    service.clock.set(NOW + 599);
    let completed = certificate(&service, &member).await;
    assert_eq!(completed.checked_at, NOW + 599);
    service.clock.set(NOW + 600);
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
}

/// Only the supplied external clock varies: authentication, signer, database,
/// membership and HTTP dispatch are their original owners. There is no accepted
/// policy/session/certificate fixture or injected owner verdict.
struct MovingClock {
    base: Arc<TestClock>,
    movement: Mutex<Option<Movement>>,
}
struct Movement {
    next: u64,
    step: i64,
    readings: Vec<u64>,
}
impl MovingClock {
    fn arm(&self, start: u64, step: i64) {
        *self.movement.lock().unwrap() = Some(Movement {
            next: start,
            step,
            readings: Vec::new(),
        });
    }
    fn finish(&self) -> Vec<u64> {
        self.movement.lock().unwrap().take().unwrap().readings
    }
}
impl Clock for MovingClock {
    fn now(&self) -> u64 {
        let mut state = self.movement.lock().unwrap();
        if let Some(movement) = state.as_mut() {
            let now = movement.next;
            movement.readings.push(now);
            movement.next = now.checked_add_signed(movement.step).unwrap();
            now
        } else {
            self.base.now()
        }
    }
}
async fn moving_community(public: &GlobalPublic) -> (Running, Arc<MovingClock>) {
    let dir = tempfile::tempdir().unwrap();
    let config = community_config(dir.path(), "alpha", public, 100);
    let base_clock = Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)));
    let clock = Arc::new(MovingClock {
        base: base_clock.clone(),
        movement: Mutex::new(None),
    });
    let door = Door::community(config, clock.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (
        Running {
            base,
            door,
            clock: base_clock,
            task,
            dir,
        },
        clock,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn http_certificate_refuses_forward_expiry_and_rollback_during_actual_owner_work() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    for step in [200, -1] {
        let (service, clock) = moving_community(&public).await;
        let member = enrol_community(&service, HOST, &passport).await;
        // Admit at the real original session time, then change the external
        // clock on each observation without relying on a fixed owner call count.
        clock.arm(NOW, step);
        let response = reqwest::Client::new()
            .post(format!("{}/v1/passkey_certificate", service.base))
            .header("host", HOST)
            .bearer_auth(&member.session)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body: Value = response.json().await.unwrap();
        let readings = clock.finish();
        assert!(
            readings.len() > 1,
            "request must observe time beyond admission"
        );
        assert!(matches!(status, 401 | 409));
        assert!(body.get("bytes").is_none());
        assert!(body.get("error").is_some());
        if step > 0 {
            assert!(readings.iter().any(|time| *time >= NOW + 600));
        } else {
            assert!(readings.iter().any(|time| *time < NOW));
        }
    }
}
