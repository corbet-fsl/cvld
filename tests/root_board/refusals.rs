use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn root_registration_refuses_an_otherwise_valid_ordinary_passport_proof() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let (board, _) = root_board(&public).await;
    let feed = feed(&board, MEMBER_HOST).await;
    let challenge: PresentationChallenge = serde_json::from_value(
        client(&board, MEMBER_HOST, None)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("root").unwrap(),
        csgn::KeyRing::from_cbor(&feed.key_ring).unwrap(),
    );
    let request = expected
        .authenticate_root_board_request(&challenge.request, NOW)
        .unwrap();
    assert_eq!(request.root().to_bytes(), descriptor(&feed, NOW).to_bytes());
    assert!(expected.authenticate(&challenge.request, NOW).is_err());
    // Deliberately answer only the original global half of the exact root
    // challenge. The ordinary proof has the right nonce, scope and passport;
    // rejection must come from the mandatory joint root purpose.
    let proof = trusted_presentation(&passport, request.global_request()).await;
    let pseudonym = cpsd::verify(
        &mut cpsd::rand::rngs::OsRng,
        std::slice::from_ref(passport.issuer()),
        request.global_request(),
        &proof,
    )
    .unwrap();
    assert_eq!(
        pseudonym,
        passport.pseudonym(&cpsd::CommunityId::new("root").unwrap())
    );
    let body = json!({"passport": {"challenge": challenge.challenge, "proof": proof.to_bytes()}});
    assert_eq!(
        call_status(&board, MEMBER_HOST, None, "register_begin", body.clone()).await,
        400
    );
    assert_eq!(
        call_status(&board, MEMBER_HOST, None, "register_begin", body).await,
        409
    );
    assert_eq!(
        call_status(
            &board,
            MEMBER_HOST,
            None,
            "register_begin",
            json!({
                "bootstrap": "synthetic-root-enrolment-capability", "passport": null,
            })
        )
        .await,
        403
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn root_constructor_revalidates_deserialized_scope_and_descriptor_bytes() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root-public");
    std::fs::write(&path, b"not a canonical public descriptor").unwrap();
    let config = community_config(dir.path(), "root", &public, 100);
    let value = json!({"community": config, "root_board_public_key_file": path});
    let parsed: RootCommunityConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(matches!(
        Door::root_board(parsed, global.clock.clone()).await,
        Err(cvld::error::Error::Invalid)
    ));
    std::fs::write(&path, public_descriptor("alpha").to_bytes()).unwrap();
    let parsed: RootCommunityConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(matches!(
        Door::root_board(parsed, global.clock.clone()).await,
        Err(cvld::error::Error::Invalid)
    ));
    let mut foreign = value;
    foreign["community"]["community"] = json!("alpha");
    let parsed: RootCommunityConfig = serde_json::from_value(foreign).unwrap();
    assert!(matches!(
        Door::root_board(parsed, global.clock.clone()).await,
        Err(cvld::error::Error::Invalid)
    ));
    let ordinary: CommunityConfig = community_config(dir.path(), "root", &public, 100);
    assert!(RootCommunityConfig::new(ordinary, String::new()).is_err());
}
