use super::*;

#[tokio::test]
async fn cancellation_before_external_dispatch_and_after_settlement_retains_unknown_across_reopen()
{
    for reply in [Reply::PauseBeforeSupported, Reply::PauseAfterSettle] {
        let directory = tempfile::tempdir().unwrap();
        let database = db(&directory.path().join("payments.db")).await;
        let config = config(directory.path());
        let clock = Time::new();
        let wire = Wire::new(reply);
        let owner = owner("member");
        let mut host = open_host(&database, config.clone(), clock.clone(), wire.clone()).await;
        let preview = prepare(&mut host, &owner);
        {
            let finish = host.execute(
                &preview.operation,
                &preview.authorization,
                &owner,
                authority(clock.clone()),
            );
            tokio::pin!(finish);
            tokio::select! {result=&mut finish=>panic!("expected pending external boundary; returned success: {}",result.is_ok()), result=tokio::time::timeout(std::time::Duration::from_secs(5),wire.entered.notified())=>result.unwrap()}
        }
        // Drop the pinned future scope (including its exclusive host borrow).
        drop(host);
        let mut reopened = open_host(&database, config, clock.clone(), wire.clone()).await;
        assert_eq!(
            reopened
                .status(&preview.operation, &owner)
                .await
                .unwrap()
                .outcome,
            PaymentOutcome::Uncertain
        );
        assert!(
            reopened
                .execute(
                    &preview.operation,
                    &preview.authorization,
                    &owner,
                    authority(clock)
                )
                .await
                .is_err()
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
        assert!(wire.settled.load(Ordering::SeqCst) <= 1);
    }
}
