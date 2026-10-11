use super::*;

#[tokio::test]
async fn stable_account_scope_key_and_budget_boundaries_refuse_before_external_io() {
    let directory = tempfile::tempdir().unwrap();
    let database = db(&directory.path().join("payments.db")).await;
    let original = config(directory.path());
    let clock = Time::new();
    let wire = Wire::new(Reply::Success);
    let mut current = open_host(&database, original.clone(), clock.clone(), wire.clone()).await;
    let owner = owner("member");
    let preview = prepare(&mut current, &owner);
    let mut other = owner.clone();
    other.session = [9; 32];
    assert!(
        current
            .execute(
                &preview.operation,
                &preview.authorization,
                &other,
                authority(clock.clone())
            )
            .await
            .is_err()
    );
    assert!(
        current
            .execute(
                &preview.operation,
                "wrong-consent",
                &owner,
                authority(clock.clone())
            )
            .await
            .is_err()
    );
    assert!(
        current
            .prepare(
                PreparationContext {
                    owner: owner.clone(),
                    session_expires: 190,
                    observed: NOW,
                    policy: PolicyBinding {
                        epoch: 1,
                        revision: 1,
                    },
                },
                "paid-access",
                payload(),
                amount(13),
            )
            .is_err()
    );
    for change in ["account", "endpoint", "key"] {
        let mut changed = original.clone();
        match change {
            "account" => changed.account = "other".into(),
            "endpoint" => changed.facilitator_url = "https://other.example.test".into(),
            _ => {
                let key = directory.path().join("other-key");
                std::fs::write(&key, [8; 32]).unwrap();
                changed.journal_key_file = key.to_str().unwrap().into();
            }
        }
        assert!(
            PaymentHost::open(
                &database,
                changed,
                "alpha".into(),
                "admission".into(),
                Arc::new(clock.clone()),
                Some(payments::transport::AnyTransport(Arc::new(Inert(
                    wire.clone()
                ))))
            )
            .await
            .is_err()
        );
    }
    clock.set(preview.expires_at);
    assert!(
        current
            .execute(
                &preview.operation,
                &preview.authorization,
                &owner,
                authority(clock)
            )
            .await
            .is_err()
    );
    assert_eq!(wire.supported.load(Ordering::SeqCst), 0);
}
