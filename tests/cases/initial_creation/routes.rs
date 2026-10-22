use super::*;

pub(super) struct Fixture {
    pub(super) service: Running,
    pub(super) member: Member,
    pub(super) passport: cpsd::Passport,
    pub(super) _global: Running,
}

pub(super) async fn fixture() -> Fixture {
    fixture_with(Some(SEED)).await
}

pub(super) async fn fixture_with(seed: Option<[u8; 32]>) -> Fixture {
    let (global, contact_wire, cohort) = contacts::production(true).await;
    let (_wallet, passport, public) = contacts::wallet(&global, cohort).await;
    assert_eq!(contact_wire.calls(), 4);
    let payment_wire = payment_support::Wire::new(payment_support::Reply::Success);
    let service = payment::community(&public, payment_wire.clone()).await;
    let proof = presentation(&service, HOST, None, &passport).await;
    let api = client(&service, HOST, None);
    let (action, request) = match seed {
        Some(seed) => (
            "initial_registration_begin",
            json!({"passport":proof,"seed":seed}),
        ),
        None => ("register_begin", json!({"passport":proof})),
    };
    let response = api.call(action, request).await.unwrap();
    let start = if seed.is_some() {
        let initial: InitialCeremony = serde_json::from_value(response).unwrap();
        assert_eq!(initial.checked_at, NOW);
        assert!(initial.expires_at > initial.checked_at);
        Ceremony {
            ceremony: initial.ceremony,
            user: initial.user,
            options: initial.options,
        }
    } else {
        serde_json::from_value(response).unwrap()
    };
    let mut authenticator = SoftToken::new(true).unwrap().0;
    let challenge: ckyh::CreationChallengeResponse = serde_json::from_value(start.options).unwrap();
    let mut options = challenge.public_key;
    options
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let credential = authenticator
        .perform_register(
            ckyh::Url::parse(&format!("https://{HOST}")).unwrap(),
            options,
            300_000,
        )
        .unwrap();
    let credential_id = credential.raw_id.as_ref().to_vec();
    let request = json!({"ceremony":start.ceremony,"credential":credential});
    let user: Registered =
        serde_json::from_value(api.call("register_finish", request.clone()).await.unwrap())
            .unwrap();
    assert_eq!(
        call_status(&service, HOST, None, "register_finish", request).await,
        401
    );
    let session = login(
        &service,
        HOST,
        &mut authenticator,
        &user.user,
        &credential_id,
    )
    .await;
    let signing_key = SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes();
    let body = proven(
        &service,
        HOST,
        &session,
        &mut authenticator,
        json!({"kind":"device_authorize","key":signing_key}),
        json!({"key":signing_key}),
    )
    .await;
    client(&service, HOST, Some(&session))
        .call("device_authorize", body)
        .await
        .unwrap();
    assert_eq!(payment_wire.supported.load(Ordering::SeqCst), 0);
    assert_eq!(payment_wire.settled.load(Ordering::SeqCst), 0);
    Fixture {
        service,
        member: Member {
            authenticator,
            user: user.user,
            credential: credential_id,
            session,
            signing_key,
        },
        passport,
        _global: global,
    }
}
