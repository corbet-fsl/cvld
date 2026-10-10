use super::*;
#[path = "../../../tests/payment_support/mod.rs"]
mod fixture;
use fixture::*;

#[tokio::test]
async fn terminal_success_and_uncertainty_forget_actual_owned_request_buffers() {
    for reply in [Reply::Success, Reply::Unknown] {
        let directory = tempfile::tempdir().unwrap();
        let database = db(&directory.path().join("payments.db")).await;
        let clock = Time::new();
        let wire = Wire::new(reply);
        let owner = owner("member");
        let mut host = open_host(&database, config(directory.path()), clock.clone(), wire).await;
        let preview = prepare(&mut host, &owner);
        {
            let prepared = host
                .flows
                .get(&preview.operation)
                .unwrap()
                .instruction
                .as_ref()
                .unwrap();
            assert!(
                String::from_utf8_lossy(prepared.evidence.expose()).contains("PRIVATE-SIGNATURE")
            );
            assert!(String::from_utf8_lossy(prepared.terms.expose()).contains("fixture-merchant"));
        }
        let receipt = host
            .execute(
                &preview.operation,
                &preview.authorization,
                &owner,
                authority(clock),
            )
            .await
            .unwrap();
        let flow = host.flows.get(&preview.operation).unwrap();
        assert!(matches!(flow.phase, Phase::Finished(_)));
        assert!(
            flow.instruction.is_none(),
            "the actual owned raw request must move out, not merely redact Debug"
        );
        assert_eq!(flow.binding.subject, "member");
        assert_ne!(flow.id, [0; 32]);
        assert_eq!(
            flow.access.is_some(),
            receipt.outcome == PaymentOutcome::Settled
        );
        let rows = database
            .community("alpha")
            .unwrap()
            .query("SELECT metadata FROM cvld_payment_operation", ())
            .await
            .unwrap();
        assert!(!rows[0].get_str(0).unwrap().contains("PRIVATE-SIGNATURE"));
        assert!(
            !rows[0]
                .get_str(0)
                .unwrap()
                .contains("PRIVATE-CHAIN-TRANSACTION")
        );
    }
}

#[tokio::test]
async fn canceling_the_real_execution_future_drops_request_buffers_from_running_owned_state() {
    for reply in [Reply::PauseBeforeSupported, Reply::PauseAfterSettle] {
        let directory = tempfile::tempdir().unwrap();
        let database = db(&directory.path().join("payments.db")).await;
        let clock = Time::new();
        let wire = Wire::new(reply);
        let owner = owner("member");
        let mut host = open_host(
            &database,
            config(directory.path()),
            clock.clone(),
            wire.clone(),
        )
        .await;
        let preview = prepare(&mut host, &owner);
        assert!(
            host.flows
                .get(&preview.operation)
                .unwrap()
                .instruction
                .is_some()
        );
        {
            let executing = host.execute(
                &preview.operation,
                &preview.authorization,
                &owner,
                authority(clock.clone()),
            );
            tokio::pin!(executing);
            tokio::select! {result=&mut executing=>panic!("expected an actual awaited boundary, got completion: {}",result.is_ok()), result=tokio::time::timeout(Duration::from_secs(5),wire.entered.notified())=>result.unwrap()}
            // End this scope to drop the original future and its borrowed host
            // lease; dropping only Pin<&mut Future> would not cancel it.
        }
        let flow = host.flows.get(&preview.operation).unwrap();
        assert!(matches!(flow.phase, Phase::Running));
        assert!(flow.instruction.is_none());
        assert!(flow.access.is_none());
        assert_eq!(
            host.status(&preview.operation, &owner)
                .await
                .unwrap()
                .outcome,
            PaymentOutcome::Uncertain
        );
        let metadata = database
            .community("alpha")
            .unwrap()
            .query("SELECT metadata FROM cvld_payment_operation", ())
            .await
            .unwrap();
        let record: serde_json::Value =
            serde_json::from_str(metadata[0].get_str(0).unwrap()).unwrap();
        assert_eq!(record["outcome"]["state"], "unknown");
        assert!(record["continuation"].is_null());
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
    }
}
