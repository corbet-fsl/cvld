use super::*;

#[tokio::test]
async fn unknown_and_post_reservation_authority_loss_never_send_another_payment() {
    for refuse_at in [usize::MAX, 1, 2, 3] {
        let directory = tempfile::tempdir().unwrap();
        let database = db(&directory.path().join("payments.db")).await;
        let clock = Time::new();
        let wire = Wire::new(Reply::Unknown);
        let owner = owner("member");
        let mut host = open_host(
            &database,
            config(directory.path()),
            clock.clone(),
            wire.clone(),
        )
        .await;
        let preview = prepare(&mut host, &owner);
        let checker = Arc::new(Authority {
            clock: clock.clone(),
            calls: 0.into(),
            refuse_at,
        });
        assert_eq!(
            host.execute(&preview.operation, &preview.authorization, &owner, checker)
                .await
                .unwrap()
                .outcome,
            PaymentOutcome::Uncertain
        );
        assert!(host.access(&preview.operation, &owner).is_err());
        assert!(
            host.execute(
                &preview.operation,
                &preview.authorization,
                &owner,
                authority(clock)
            )
            .await
            .is_err()
        );
        assert_eq!(
            wire.settled.load(Ordering::SeqCst),
            usize::from(refuse_at == usize::MAX)
        );
        assert_eq!(
            database
                .community("alpha")
                .unwrap()
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
    }
}
