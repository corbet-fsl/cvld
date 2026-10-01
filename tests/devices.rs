#![cfg(feature = "development-gate")]
mod support;
use cvld::api::*;
use serde_json::{Value, json};
use support::*;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

async fn begin(service: &Running, host: &str, session: &str) -> (String, Value) {
    let response = client(service, host, Some(session))
        .call("passkey_add", json!({"step":"begin"}))
        .await
        .unwrap();
    assert_eq!(response["step"], "challenge");
    (
        response["ceremony"].as_str().unwrap().into(),
        response["options"].clone(),
    )
}
fn register(
    token: &mut SoftToken,
    host: &str,
    options: Value,
) -> ckyh::RegisterPublicKeyCredential {
    let options: ckyh::CreationChallengeResponse = serde_json::from_value(options).unwrap();
    token
        .perform_register(
            ckyh::Url::parse(&format!("https://{host}")).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
                let mut options = options.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap()
        .into()
}

#[tokio::test(flavor = "multi_thread")]
async fn additional_device_is_session_bound_and_survives_original_revocation() {
    let global = global(100).await;
    let (wallet, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let host = "api.alpha.example.test";
    let mut first = enrol_community(&service, host, &passport).await;
    let first_client = client(&service, host, Some(&first.session));
    first_client
        .call("handle_reserve", json!({"handle":"member_one"}))
        .await
        .unwrap();
    let before: Lobby =
        serde_json::from_value(first_client.call("lobby", json!({})).await.unwrap()).unwrap();
    first_client
        .call(
            "gate_voucher",
            voucher(
                "alpha",
                &before.member_id,
                "additional-key-voucher",
                NOW + 86400,
            ),
        )
        .await
        .unwrap();
    assert!(
        issue_community(&service, host, &first, &passport)
            .await
            .credential
            .is_some()
    );
    assert_eq!(
        call_status(&service, host, None, "passkey_add", json!({"step":"begin"})).await,
        401
    );
    assert_eq!(
        call_status(
            &global,
            WALLET,
            Some(&wallet.session),
            "passkey_add",
            json!({"step":"begin"})
        )
        .await,
        421
    );

    // UV-less creation cannot be turned into another key with a bearer alone.
    let (ceremony, mut options) = begin(&service, host, &first.session).await;
    options["publicKey"]["authenticatorSelection"]["userVerification"] = json!("discouraged");
    let response = register(&mut SoftToken::new(true).unwrap().0, host, options);
    let body = json!({"step":"finish","ceremony":ceremony,"credential":response});
    assert_eq!(
        call_status(
            &service,
            host,
            Some(&first.session),
            "passkey_add",
            body.clone()
        )
        .await,
        409
    );
    assert_eq!(
        call_status(&service, host, Some(&first.session), "passkey_add", body).await,
        401
    );

    let alternate_session = login(
        &service,
        host,
        &mut first.authenticator,
        &first.user,
        &first.credential,
    )
    .await;
    let (old_ceremony, old_options) = begin(&service, host, &first.session).await;
    let (ceremony, options) = begin(&service, host, &first.session).await;
    let old_response = register(&mut SoftToken::new(true).unwrap().0, host, old_options);
    assert_eq!(
        call_status(
            &service,
            host,
            Some(&first.session),
            "passkey_add",
            json!({"step":"finish","ceremony":old_ceremony,"credential":old_response})
        )
        .await,
        401
    );
    let mut second = SoftToken::new(true).unwrap().0;
    let response = register(&mut second, host, options);
    let credential = response.raw_id.as_ref().to_vec();
    let body = json!({"step":"finish","ceremony":ceremony,"credential":response});
    // A different live session of the same key cannot consume the ceremony.
    assert_eq!(
        call_status(
            &service,
            host,
            Some(&alternate_session),
            "passkey_add",
            body.clone()
        )
        .await,
        401
    );
    let added: AddedPasskey = serde_json::from_value(
        first_client
            .call("passkey_add", body.clone())
            .await
            .unwrap(),
    )
    .unwrap();
    let AddedPasskey::Registered {
        user,
        credential: registered,
    } = added
    else {
        panic!("registration result")
    };
    assert_eq!(user, first.user);
    assert_eq!(registered, credential);
    assert_eq!(
        call_status(&service, host, Some(&first.session), "passkey_add", body).await,
        401
    );
    let session = login(&service, host, &mut second, &user, &credential).await;
    let second = Member {
        authenticator: second,
        user,
        credential,
        session,
    };
    let second_client = client(&service, host, Some(&second.session));
    let (pending, options) = begin(&service, host, &first.session).await;
    let pending_response = register(&mut SoftToken::new(true).unwrap().0, host, options);
    second_client
        .call("passkey_revoke", json!({"credential":first.credential}))
        .await
        .unwrap();
    for session in [&first.session, &alternate_session] {
        assert_eq!(
            call_status(&service, host, Some(session), "lobby", json!({})).await,
            401
        );
    }
    assert_eq!(
        call_status(
            &service,
            host,
            Some(&second.session),
            "passkey_add",
            json!({"step":"finish","ceremony":pending,"credential":pending_response})
        )
        .await,
        401
    );
    let after: Lobby =
        serde_json::from_value(second_client.call("lobby", json!({})).await.unwrap()).unwrap();
    assert_eq!(after.member_id, before.member_id);
    assert_eq!(after.handle, before.handle);
    assert!(
        issue_community(&service, host, &second, &passport)
            .await
            .credential
            .is_some()
    );
    second_client
        .call("passkey_revoke", json!({"credential":second.credential}))
        .await
        .unwrap();
    assert_eq!(
        call_status(&service, host, Some(&second.session), "lobby", json!({})).await,
        401
    );
    let proof = presentation(&service, host, None, &passport).await;
    assert_eq!(
        call_status(
            &service,
            host,
            None,
            "register_begin",
            json!({"passport":proof})
        )
        .await,
        409
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn additional_registration_expires_and_logout_invalidates_pending_state() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let host = "api.alpha.example.test";
    let mut member = enrol_community(&service, host, &passport).await;
    let (ceremony, options) = begin(&service, host, &member.session).await;
    let response = register(&mut SoftToken::new(true).unwrap().0, host, options);
    service.clock.set(NOW + 301);
    assert_eq!(
        call_status(
            &service,
            host,
            Some(&member.session),
            "passkey_add",
            json!({"step":"finish","ceremony":ceremony,"credential":response})
        )
        .await,
        401
    );
    let (ceremony, options) = begin(&service, host, &member.session).await;
    let response = register(&mut SoftToken::new(true).unwrap().0, host, options);
    client(&service, host, Some(&member.session))
        .call("logout", json!({}))
        .await
        .unwrap();
    let new_session = login(
        &service,
        host,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    assert_eq!(
        call_status(
            &service,
            host,
            Some(&new_session),
            "passkey_add",
            json!({"step":"finish","ceremony":ceremony,"credential":response})
        )
        .await,
        401
    );
    let (ceremony, options) = begin(&service, host, &new_session).await;
    let response = register(&mut SoftToken::new(true).unwrap().0, host, options);
    service.clock.set(NOW + 902);
    assert_eq!(
        call_status(
            &service,
            host,
            Some(&new_session),
            "passkey_add",
            json!({"step":"finish","ceremony":ceremony,"credential":response})
        )
        .await,
        401
    );
}
