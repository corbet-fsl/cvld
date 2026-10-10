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
    let keyhole = ckyh::Passkeys::new(
        ckyh::LibsqlStore::new(&database, "alpha", tokio::runtime::Handle::current()).unwrap(),
        "alpha",
        HOST,
        &[ckyh::Url::parse(&format!("https://{HOST}")).unwrap()],
    )
    .unwrap();
    *remote.original.lock().unwrap() = Some((
        keyhole,
        ckyh::Uuid::parse_str(&member.user).unwrap(),
        member.credential.clone().into(),
    ));
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
