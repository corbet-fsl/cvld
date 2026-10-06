#![cfg(feature = "development-gate")]

mod support;
use cvld::api::{Ceremony, DiscoverableCeremony, GlobalPublic, RegisteredUser, Role, Session};
use serde_json::{Value, json};
use support::{
    resident::{Resident, strip_prf},
    *,
};

async fn post(
    service: &Running,
    host: &str,
    origin: &str,
    action: &str,
    body: Value,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/v1/{action}", service.base))
        .header("host", host)
        .header("origin", origin)
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn success(service: &Running, host: &str, origin: &str, action: &str, body: Value) -> Value {
    let response = post(service, host, origin, action, body).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        origin
    );
    response.json().await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn global_and_operator_vault_origins_complete_real_discoverable_login_without_widening_rp() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community("alpha", &public).await;
    for (service, host, rp, bootstrap, role) in [
        (&global, WALLET, WALLET, None, Role::Member),
        (
            &global,
            ROOT,
            "root.example.test",
            Some("synthetic-operator-enrolment-capability"),
            Role::Root,
        ),
        (
            &community,
            "api.admin.alpha.example.test",
            "alpha.example.test",
            Some("synthetic-admin-enrolment-capability"),
            Role::Admin,
        ),
        (
            &community,
            ROOT,
            "root.example.test",
            Some("synthetic-root-enrolment-capability"),
            Role::Root,
        ),
    ] {
        let origin = format!("https://vault.{rp}");
        let start: Ceremony = serde_json::from_value(
            success(
                service,
                host,
                &origin,
                "register_begin",
                json!({"bootstrap": bootstrap, "passport": null}),
            )
            .await,
        )
        .unwrap();
        assert_eq!(start.options["publicKey"]["rp"]["id"], rp);
        let mut resident = Resident::default();
        let mut credential = resident.ceremony(start.options, true, &origin).await;
        drop(strip_prf(&mut credential));
        let user: RegisteredUser = serde_json::from_value(
            success(
                service,
                host,
                &origin,
                "register_finish",
                json!({"ceremony": start.ceremony, "credential": credential}),
            )
            .await,
        )
        .unwrap();

        for forbidden in [
            "https://vault.foreign.example.test".to_owned(),
            format!("{origin}.evil.test"),
            format!("{origin}:444"),
            format!("{origin}."),
        ] {
            let response = post(
                service,
                host,
                &forbidden,
                "login_discoverable_begin",
                json!({}),
            )
            .await;
            assert_eq!(response.status(), 403, "{host}: {forbidden}");
            assert!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .is_none()
            );
        }

        // The same RP can produce a genuine signature in another subdomain;
        // neither an allowed HTTP Origin header nor a correct RP can hide a
        // disallowed origin authenticated inside clientDataJSON.
        let wrong: DiscoverableCeremony = serde_json::from_value(
            success(
                service,
                host,
                &origin,
                "login_discoverable_begin",
                json!({}),
            )
            .await,
        )
        .unwrap();
        assert_eq!(wrong.options["publicKey"]["rpId"], rp);
        let mut credential = resident
            .ceremony(wrong.options, false, &format!("https://other.{rp}"))
            .await;
        drop(strip_prf(&mut credential));
        let response = post(
            service,
            host,
            &origin,
            "login_finish",
            json!({
                "ceremony": wrong.ceremony, "credential": credential,
            }),
        )
        .await;
        assert_eq!(response.status(), 401);

        let challenge: DiscoverableCeremony = serde_json::from_value(
            success(
                service,
                host,
                &origin,
                "login_discoverable_begin",
                json!({}),
            )
            .await,
        )
        .unwrap();
        assert_eq!(challenge.options["publicKey"]["rpId"], rp);
        let mut credential = resident.ceremony(challenge.options, false, &origin).await;
        drop(strip_prf(&mut credential));
        let body = json!({"ceremony": challenge.ceremony, "credential": credential});
        let session: Session = serde_json::from_value(
            success(service, host, &origin, "login_finish", body.clone()).await,
        )
        .unwrap();
        assert_eq!(session.user, user.user);
        assert_eq!(session.role, role);
        assert!(session.expires > NOW);
        assert!(!session.token.is_empty());
        assert_eq!(
            post(service, host, &origin, "login_finish", body)
                .await
                .status(),
            401
        );
    }
}
