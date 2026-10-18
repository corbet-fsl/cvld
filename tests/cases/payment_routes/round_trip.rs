use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_registry_settlement_paid_gate_and_signed_community_credential_round_trip() {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let wire = Wire::new(Reply::Success);
    let service = configured(
        &public,
        payments::transport::AnyTransport(Arc::new(Inert(wire.clone()))),
        true,
    )
    .await;
    let member = enrol_community(&service, HOST, &passport).await;
    let api = client(&service, HOST, Some(&member.session));
    // Genuine membership issuance also requires a reserved community handle.
    let reserved: Lobby = serde_json::from_value(
        api.call("handle_reserve", json!({"handle":"member_paid_access"}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reserved.handle.as_deref(), Some("member_paid_access"));
    let offer = api.call("payment_offer", json!({})).await.unwrap();
    assert_eq!(offer["access"]["level"], "caller-level");
    assert!(offer["payment_required"].is_string());
    let preview = api.call("payment_plan", plan()).await.unwrap();
    assert_eq!(preview["maximum"]["atoms"], 4);
    assert_eq!(wire.supported.load(Ordering::SeqCst), 0);
    let result = execute(&service, &member, &preview).await;
    assert_eq!(result["outcome"], "settled");
    assert_eq!(result["access"]["level"], "caller-level");
    let serialized = serde_json::to_string(&result).unwrap();
    for raw in [
        "PRIVATE-PAYER",
        "PRIVATE-CHAIN-TRANSACTION",
        "PRIVATE-SIGNATURE",
        "fixture-asset",
        "transaction",
        "currency",
        "actual_fee",
    ] {
        assert!(!serialized.contains(raw));
    }
    let accepted = api
        .call("payment_accept", json!({"operation":preview["operation"]}))
        .await
        .unwrap();
    assert_eq!(accepted["access"]["level"], "caller-level");
    assert_eq!(wire.settled.load(Ordering::SeqCst), 1);
    let credential = issue_community(&service, HOST, &member, &passport).await;
    assert_eq!(credential.lobby.state, "admitted");
    assert_eq!(credential.lobby.handle, reserved.handle);
    assert!(credential.credential.is_some());
    let bytes = credential.credential.unwrap();
    let feed: TrustFeed = serde_json::from_value(
        client(&service, HOST, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    let signed = ring.verify(&bytes, csgn::Kind::Credential, NOW).unwrap();
    let claims: cmty::cplc::Credential = serde_json::from_slice(signed.payload()).unwrap();
    assert_eq!(claims.handle, "member_paid_access");
    assert_eq!(claims.gates.len(), 1);
    assert_eq!(claims.gates[0].gate, "crpt");
    assert_eq!(claims.gates[0].provider, "fixture-facilitator");
    // The domain/host journal is real libSQL, with original raw chain reference
    // omitted even though genuine settlement feeds an actual retained gate.
    let database = crlt::Db::open(crlt::Config::new(
        format!(
            "file://{}",
            service.dir.path().join("community.db").display()
        ),
        "",
    ))
    .await
    .unwrap();
    database
        .migrate(&cvld::service::community_migrations())
        .await
        .unwrap();
    let scope = database.community("alpha").unwrap();
    let metadata = scope
        .query("SELECT metadata FROM cvld_payment_operation", ())
        .await
        .unwrap()[0]
        .get_str(0)
        .unwrap()
        .to_owned();
    assert!(!metadata.contains("PRIVATE-CHAIN-TRANSACTION"));
    let retained = scope
        .query(
            "SELECT valid_until FROM cgts_results WHERE subject = ?1",
            [credential.lobby.member_id],
        )
        .await
        .unwrap();
    assert!(!retained.is_empty());
}
