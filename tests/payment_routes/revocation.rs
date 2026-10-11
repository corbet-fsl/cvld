use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_original_passkey_revoked_after_reservation_and_discovery_prevents_verify_and_settle()
 {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let wire = Wire::new(Reply::Success);
    let remote = Arc::new(RevokingWire {
        wire: wire.clone(),
        original: std::sync::Mutex::new(None),
    });
    let service = configured(
        &public,
        payments::transport::AnyTransport(remote.clone()),
        true,
    )
    .await;
    let member = enrol_community(&service, HOST, &passport).await;
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
    // Match the original Membership's namespace, RP ID and allowed origins.
    // The API host is an origin; the RP ID is the parent community domain.
    let community = "alpha";
    let rp_id = format!("{community}.{DOMAIN}");
    let keyhole = ckyh::Passkeys::new(
        ckyh::LibsqlStore::new(&database, community, tokio::runtime::Handle::current()).unwrap(),
        community,
        &rp_id,
        &[
            ckyh::Url::parse(&format!("https://{HOST}")).unwrap(),
            ckyh::Url::parse(&format!("https://{rp_id}")).unwrap(),
            ckyh::Url::parse(&format!("https://vault.{rp_id}")).unwrap(),
        ],
    )
    .unwrap();
    let user = ckyh::Uuid::parse_str(&member.user).unwrap();
    let credential: ckyh::CredentialID = member.credential.clone().into();
    let original = tokio::task::spawn_blocking(move || {
        let registered = keyhole.list(user).unwrap();
        assert_eq!(registered.len(), 1);
        assert_eq!(registered[0].community(), community);
        assert_eq!(registered[0].member(), user);
        assert_eq!(registered[0].credential_id(), &credential);
        assert!(!registered[0].is_revoked());
        (keyhole, user, credential)
    })
    .await
    .unwrap();
    *remote.original.lock().unwrap() = Some(original);
    let preview = client(&service, HOST, Some(&member.session))
        .call("payment_plan", plan())
        .await
        .unwrap();
    assert_ne!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "payment_execute",
            json!({"operation":preview["operation"],"authorization":preview["authorization"]})
        )
        .await,
        200
    );
    assert_eq!(wire.supported.load(Ordering::SeqCst), 1);
    assert_eq!(wire.verified.load(Ordering::SeqCst), 0);
    assert_eq!(wire.settled.load(Ordering::SeqCst), 0);
    let scope = database.community("alpha").unwrap();
    let budget = scope
        .query(
            "SELECT exposure FROM cvld_payment_budget WHERE id = ?1",
            ["fees"],
        )
        .await
        .unwrap();
    assert_eq!(budget[0].get_i64(0).unwrap(), 4);
    let record: Value = serde_json::from_str(
        scope
            .query("SELECT metadata FROM cvld_payment_operation", ())
            .await
            .unwrap()[0]
            .get_str(0)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(record["outcome"]["state"], "unknown");
    assert!(record["continuation"].is_null());
}
