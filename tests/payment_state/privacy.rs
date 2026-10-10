use super::*;

#[tokio::test]
async fn real_settlement_projects_access_and_persists_no_raw_chain_or_provider_data() {
    let directory = tempfile::tempdir().unwrap();
    let database = db(&directory.path().join("payments.db")).await;
    let config = config(directory.path());
    let clock = Time::new();
    let wire = Wire::new(Reply::Success);
    let owner = owner("member");
    let mut host = open_host(&database, config.clone(), clock.clone(), wire.clone()).await;
    let preview = prepare(&mut host, &owner);
    assert_eq!(wire.settled.load(Ordering::SeqCst), 0);
    let receipt = host
        .execute(
            &preview.operation,
            &preview.authorization,
            &owner,
            authority(clock.clone()),
        )
        .await
        .unwrap();
    assert_eq!(receipt.outcome, PaymentOutcome::Settled);
    assert_eq!(receipt.access.unwrap().level, "caller-level");
    let access = host.access(&preview.operation, &owner).unwrap();
    let (_, period) = access
        .in_context(
            &cpmt::payments::Binding {
                scope: "alpha".into(),
                subject: "member".into(),
                action: "admission".into(),
            },
            NOW,
        )
        .unwrap();
    assert_eq!(period.end, 864000);
    let scope = database.community("alpha").unwrap();
    let rows = scope
        .query("SELECT metadata FROM cvld_payment_operation", ())
        .await
        .unwrap();
    let metadata = rows[0].get_str(0).unwrap();
    for raw in [
        "PRIVATE-PAYER",
        "PRIVATE-NONCE",
        "PRIVATE-SIGNATURE",
        "PRIVATE-KYC",
        "PRIVATE-CHAIN-TRANSACTION",
        "eip155:8453",
        "fixture-asset",
        "fixture-merchant",
    ] {
        assert!(!metadata.contains(raw), "{raw}");
    }
    assert!(serde_json::from_str::<serde_json::Value>(metadata).unwrap()["continuation"].is_null());
    assert_eq!(
        scope
            .query(
                "SELECT exposure FROM cvld_payment_budget WHERE id = ?1",
                ["fees"]
            )
            .await
            .unwrap()[0]
            .get_i64(0)
            .unwrap(),
        4
    );
    assert!(matches!(
        host.execute(
            &preview.operation,
            &preview.authorization,
            &owner,
            authority(clock.clone())
        )
        .await,
        Err(Error::Conflict)
    ));
    assert_eq!(wire.settled.load(Ordering::SeqCst), 1);
    drop(host);
    let reopened = open_host(&database, config, clock, wire.clone()).await;
    let status = reopened.status(&preview.operation, &owner).await.unwrap();
    assert_eq!(status.outcome, PaymentOutcome::Settled);
    assert!(status.access.is_none());
    assert!(reopened.access(&preview.operation, &owner).is_err());
    assert!(
        reopened
            .status(&preview.operation, &payment_support::owner("other"))
            .await
            .is_err()
    );
    assert_eq!(wire.settled.load(Ordering::SeqCst), 1);
}
