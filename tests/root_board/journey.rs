use super::*;

/// The real global door issues into an opaque holder. The root credential below
/// is a cryptographic fixture issued by its actual purpose key; it does not
/// claim to exercise the still-missing remote source-role authorization service.
pub(super) async fn opaque_passport(global: &Running) -> (cpsd::OpaqueHolder, GlobalPublic) {
    use cvld::api::Bytes;
    let member = enrol(global, WALLET, None).await;
    let client = client(global, WALLET, Some(&member.session));
    client.call("development_gate", json!({})).await.unwrap();
    let public: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed_and_sealing_key(
        &mut [71; 32],
        &mut [72; 32],
        b"root-door-fixture",
    )
    .unwrap();
    let challenge: Bytes =
        serde_json::from_value(client.call("passport_challenge", json!({})).await.unwrap())
            .unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let request = holder
        .begin_issuance(&mut cpsd::rand::rngs::OsRng, &issuer, &challenge)
        .unwrap();
    let blind: Bytes = serde_json::from_value(
        client
            .call(
                "passport_issue",
                json!({"challenge": challenge.to_bytes().to_vec(), "request": request.to_bytes()}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    holder
        .finish_issuance(&cpsd::BlindPassport::from_bytes(&blind.bytes).unwrap())
        .unwrap();
    (holder, public)
}

pub(super) async fn root_presentation(
    board: &Running,
    holder: &cpsd::OpaqueHolder,
    session: Option<&str>,
) -> cvld::api::PresentationInput {
    let challenge: PresentationChallenge = serde_json::from_value(
        client(board, MEMBER_HOST, session)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let public = feed(board, MEMBER_HOST).await;
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("root").unwrap(),
        csgn::KeyRing::from_cbor(&public.key_ring).unwrap(),
    );
    let proof = holder
        .present_root_board(
            &mut cpsd::rand::rngs::OsRng,
            &expected,
            &challenge.request,
            NOW,
        )
        .unwrap();
    cvld::api::PresentationInput {
        challenge: challenge.challenge,
        proof: proof.to_bytes(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_joint_http_registration_voucher_and_renewal_remain_ordinary_membership() {
    use cvld::api::{Ceremony, CredentialResponse};
    let global = global(100).await;
    let (mut holder, public) = opaque_passport(&global).await;
    let source = community("alpha", &public).await;
    let mut rng = cpsd::rand::rngs::OsRng;
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("root-door-purpose").unwrap(),
        vec![cpsd::GateId::new("root-board").unwrap()],
    )
    .unwrap();
    let configured = cpsd::RootBoardPublicKey::from_authenticated_beacon(
        issuer.public_key().clone(),
        cpsd::CommunityId::new("root").unwrap(),
        1,
        NOW / cpsd::ROOT_BOARD_COHORT_SECONDS * cpsd::ROOT_BOARD_COHORT_SECONDS,
    )
    .unwrap();
    let board = root_with_descriptor(&public, &configured).await;
    let current = descriptor(&feed(&board, MEMBER_HOST).await, NOW);

    // Authenticate the real source request under that source's original ring.
    let source_feed = feed(&source, "api.alpha.example.test").await;
    let source_anchor = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("alpha").unwrap(),
        csgn::KeyRing::from_cbor(&source_feed.key_ring).unwrap(),
    );
    let source_challenge: PresentationChallenge = serde_json::from_value(
        client(&source, "api.alpha.example.test", None)
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let request = source_anchor
        .authenticate(&source_challenge.request, NOW)
        .unwrap();
    let context = cpsd::RootBoardIssuanceContext::new(&mut rng, request, current.clone()).unwrap();
    // An actual signer authenticates only this fixture's root issuance context.
    // The root member door never receives this signer, source proof or issuer key.
    let mut fixture_signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "root",
        csgn::SecretKey::from_seed(&mut [73; 32]),
        NOW - 1,
        86_400,
    )
    .await
    .unwrap();
    let signed = fixture_signer
        .sign(
            csgn::Kind::Credential,
            &context.to_bytes(),
            NOW,
            context.deadline() + 1,
        )
        .await
        .unwrap();
    let fixture_anchor = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("root").unwrap(),
        fixture_signer.key_ring().unwrap().clone(),
    );
    let request = holder
        .begin_root_board_issuance(
            &mut rng,
            &fixture_anchor,
            &signed,
            &source_anchor,
            &source_challenge.request,
            NOW,
        )
        .unwrap();
    let verified = cpsd::verify_root_board_issuance(
        &[cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap()],
        &context,
        &request,
        NOW,
    )
    .unwrap();
    let credential =
        cpsd::issue_blind_root_board(&mut rng, &issuer, &current, verified, NOW).unwrap();
    holder.finish_root_board_issuance(&credential).unwrap();

    let proof = root_presentation(&board, &holder, None).await;
    let body = json!({"passport": proof});
    let start: Ceremony = serde_json::from_value(
        client(&board, MEMBER_HOST, None)
            .call("register_begin", body.clone())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        call_status(&board, MEMBER_HOST, None, "register_begin", body).await,
        409
    );
    let member = finish_enrol(&board, MEMBER_HOST, start).await;
    let client = client(&board, MEMBER_HOST, Some(&member.session));
    let member_id = holder
        .pseudonym(&cpsd::CommunityId::new("root").unwrap())
        .to_hex();
    client
        .call("handle_reserve", json!({"handle":"root_member"}))
        .await
        .unwrap();
    let receipt = voucher("root", &member_id, "root-door-voucher", NOW + 172_800);
    client.call("gate_voucher", receipt.clone()).await.unwrap();
    assert!(client.call("gate_voucher", receipt).await.is_err());
    // The first member of the board is its Root, founded by the one-use Global Root
    // creation entitlement; the second pass is an ordinary renewal.
    let mut creation = active::creation_invitation(&board, "root", &public, &member).await;
    for _ in 0..2 {
        let proof = root_presentation(&board, &holder, Some(&member.session)).await;
        let body = json!({"presentation":proof,"devices":[member.signing_key]});
        let body = match creation.take() {
            Some(invitation) => {
                let mut value = body;
                value["creation"] = json!(invitation);
                value
            }
            None => body,
        };
        let issued: CredentialResponse =
            serde_json::from_value(client.call("credential_issue", body.clone()).await.unwrap())
                .unwrap();
        assert_eq!(issued.lobby.state, "admitted");
        let feed = feed(&board, MEMBER_HOST).await;
        let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
        let cose = issued.credential.unwrap();
        let verified = ring.verify(&cose, csgn::Kind::Credential, NOW).unwrap();
        assert!(verified.valid_until() <= current.expires_at());
        let claims: cmty::cplc::Credential = serde_json::from_slice(verified.payload()).unwrap();
        assert_eq!(claims.community, "root");
        assert_eq!(claims.member, member_id);
        assert_eq!(claims.gates.len(), 1);
        assert_eq!(claims.gates[0].gate, "cvch");
        let text = std::str::from_utf8(verified.payload()).unwrap();
        for hidden in ["alpha", "root-board", "development", "role"] {
            assert!(!text.contains(hidden));
        }
        assert_eq!(
            call_status(
                &board,
                MEMBER_HOST,
                Some(&member.session),
                "credential_issue",
                body
            )
            .await,
            409
        );
    }
    assert_eq!(
        call_status(
            &board,
            MEMBER_HOST,
            Some(&member.session),
            "schema_check",
            json!({"schema":community_schema("root", 2)})
        )
        .await,
        403
    );
}
