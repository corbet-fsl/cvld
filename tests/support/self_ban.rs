//! Real UV resident wallets and the permanent holder-only self-ban ceremony.
#![allow(dead_code)]
use super::{
    resident::{Resident, strip_prf},
    *,
};
use cvld::api::*;
use cvld::service::Clock;
use serde_json::{Value, json};

pub struct Wallet {
    pub device: Resident,
    pub session: Session,
    pub credential: Vec<u8>,
}
pub async fn discover(service: &Running, host: &str, device: &mut Resident) -> Session {
    let api = client(service, host, None);
    let begin: DiscoverableCeremony = serde_json::from_value(
        api.call("login_discoverable_begin", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut credential = device
        .ceremony(begin.options, false, &format!("https://{host}"))
        .await;
    strip_prf(&mut credential);
    serde_json::from_value(
        api.call(
            "login_finish",
            json!({"ceremony":begin.ceremony,"credential":credential}),
        )
        .await
        .unwrap(),
    )
    .unwrap()
}
pub async fn wallet(service: &Running, host: &str, bootstrap: Option<&str>) -> Wallet {
    let api = client(service, host, None);
    let begin: Ceremony = serde_json::from_value(
        api.call("register_begin", json!({"bootstrap":bootstrap}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut device = Resident::default();
    let mut credential = device
        .ceremony(begin.options, true, &format!("https://{host}"))
        .await;
    strip_prf(&mut credential);
    let id: ckyh::RegisterPublicKeyCredential = serde_json::from_value(credential.clone()).unwrap();
    let id = id.raw_id.as_ref().to_vec();
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
    assert_eq!(user.user, session.user);
    Wallet {
        device,
        session,
        credential: id,
    }
}
pub async fn confirmation(service: &Running, owner: &mut Wallet) -> Value {
    let api = client(service, WALLET, Some(&owner.session.token));
    let challenge: SelfBanChallenge =
        serde_json::from_value(api.call("global_self_ban_begin", json!({})).await.unwrap())
            .unwrap();
    assert!(matches!(
        challenge.intent,
        SelfBanIntent::PermanentGlobalSelfBan
    ));
    assert!(challenge.warning.contains("permanent"));
    assert!(challenge.warning.contains("no undo"));
    assert_eq!(challenge.expires, service.clock.now() + 300);
    assert_eq!(
        challenge.options["publicKey"]["userVerification"],
        "required"
    );
    let mut credential = owner
        .device
        .ceremony(challenge.options, false, &format!("https://{WALLET}"))
        .await;
    strip_prf(&mut credential);
    json!({"ceremony":challenge.ceremony,"credential":credential})
}

/// Complete the permanent self-ban of one resident wallet; it advances the global epoch.
pub async fn self_ban(service: &Running, owner: &mut Wallet) {
    let body = confirmation(service, owner).await;
    assert_eq!(
        call_status(
            service,
            WALLET,
            Some(&owner.session.token),
            "global_self_ban_finish",
            body
        )
        .await,
        200
    );
}
