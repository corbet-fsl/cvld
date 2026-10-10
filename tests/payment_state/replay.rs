use super::*;

#[tokio::test]
async fn actual_domain_reuses_unknown_or_success_journal_record_without_external_resettlement() {
    for response in [Reply::Unknown, Reply::Success] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("payments.db");
        let database = db(&path).await;
        let configured = config(directory.path());
        let clock = Time::new();
        let wire = Wire::new(response);
        let request = instruction([7; 32]);
        let payments = domain(&database, &configured, clock.clone(), wire.clone()).await;
        let first = payments
            .dispatch(&request, permit(&payments, &request), NOW)
            .await
            .unwrap();
        let expected = first.outcome.state();
        assert!(matches!(
            expected,
            cpmt::payments::State::Unknown | cpmt::payments::State::Settled
        ));
        assert_eq!(wire.settled.load(Ordering::SeqCst), 1);
        drop(payments);
        drop(database);
        let database = db(&path).await;
        let reopened = domain(&database, &configured, clock, wire.clone()).await;
        let repeated = reopened
            .dispatch(&request, permit(&reopened, &request), NOW)
            .await
            .unwrap();
        assert_eq!(repeated.outcome.state(), expected);
        assert_eq!(wire.settled.load(Ordering::SeqCst), 1);
        assert!(repeated.member_action.is_none());
        if expected == cpmt::payments::State::Unknown {
            assert!(
                repeated
                    .outcome
                    .evidence(
                        &request.binding,
                        cpmt::payments::State::Settled,
                        NOW,
                        864000
                    )
                    .is_err()
            );
        }
        let mut changed = instruction([7; 32]);
        changed.evidence = cpmt::payments::Private::new(b"changed-input".to_vec());
        assert!(matches!(
            reopened
                .dispatch(&changed, permit(&reopened, &changed), NOW)
                .await,
            Err(cpmt::payments::Error::Conflict)
        ));
        assert_eq!(wire.settled.load(Ordering::SeqCst), 1);
        assert!(
            reopened
                .observation(&request.id, &request.binding, [8; 32], 190)
                .await
                .is_err(),
            "raw chain authority is absent after restart"
        );
    }
}
