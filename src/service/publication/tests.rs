use super::*;
use crate::test_support::{NOW, TestClock};

fn publication(clock: Arc<TestClock>, effect: Effect) -> Publication {
    Publication::new(
        clock,
        &Context {
            host: "wallet.example.test".into(),
            grant: None,
            token: None,
            now: NOW,
            authentication: None,
        },
        effect,
    )
}

#[tokio::test]
async fn publication_checks_consumed_deadlines_and_preserves_operation_results() {
    assert!(expires_at(0).is_ok()); // Direct calls do not invent request authority.
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let value = publication(clock.clone(), Effect::Record)
        .run(async {
            expires_at(NOW + 10)?;
            expires_at(NOW + 20)?;
            clock.set(NOW + 9);
            Ok(42)
        })
        .await
        .unwrap();
    assert_eq!(value, 42);
    assert!(matches!(
        publication(clock.clone(), Effect::Check)
            .run(async { Err::<(), _>(Error::Refused) })
            .await,
        Err(Error::Refused)
    ));
    for effect in [Effect::Check, Effect::Record] {
        clock.set(NOW);
        let result = publication(clock.clone(), effect)
            .run(async {
                expires_at(NOW + 10)?;
                expires_at(NOW + 20)?;
                clock.set(NOW + 10);
                Ok(())
            })
            .await;
        assert!(matches!(
            (effect, result),
            (Effect::Check, Err(Error::Unauthorized)) | (Effect::Record, Err(Error::Reconcile))
        ));
    }
}

#[tokio::test]
async fn rollback_is_sticky_and_an_expired_start_never_executes() {
    let clock = Arc::new(TestClock(AtomicU64::new(NOW - 1)));
    assert!(matches!(
        publication(clock.clone(), Effect::Record)
            .run(async {
                panic!("an invalid authorization must not execute");
                #[allow(unreachable_code)]
                Ok::<(), Error>(())
            })
            .await,
        Err(Error::Unauthorized)
    ));
    clock.set(NOW);
    assert!(matches!(
        publication(clock.clone(), Effect::Record)
            .run(async {
                clock.set(NOW - 1);
                assert!(matches!(expires_at(NOW + 10), Err(Error::Unauthorized)));
                clock.set(NOW + 1);
                Ok(())
            })
            .await,
        Err(Error::Reconcile)
    ));
    clock.set(NOW);
    assert!(matches!(
        publication(clock, Effect::Check)
            .run(async { expires_at(NOW) })
            .await,
        Err(Error::Unauthorized)
    ));
}
