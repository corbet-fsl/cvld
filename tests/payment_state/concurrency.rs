use super::*;

#[tokio::test]
async fn concurrent_domain_operations_atomically_share_the_operator_fee_budget() {
    let directory = tempfile::tempdir().unwrap();
    let database = db(&directory.path().join("payments.db")).await;
    let configured = config(directory.path());
    let clock = Time::new();
    let wire = Wire::new(Reply::Unknown);
    let first = domain(&database, &configured, clock.clone(), wire.clone()).await;
    let second = domain(&database, &configured, clock.clone(), wire.clone()).await;
    let third = domain(&database, &configured, clock.clone(), wire.clone()).await;
    let fourth = domain(&database, &configured, clock, wire.clone()).await;
    let (a, b, c, d) = (
        instruction([1; 32]),
        instruction([2; 32]),
        instruction([3; 32]),
        instruction([4; 32]),
    );
    let results = tokio::join!(
        first.dispatch(&a, permit(&first, &a), NOW),
        second.dispatch(&b, permit(&second, &b), NOW),
        third.dispatch(&c, permit(&third, &c), NOW),
        fourth.dispatch(&d, permit(&fourth, &d), NOW)
    );
    assert_eq!(
        [results.0, results.1, results.2, results.3]
            .iter()
            .filter(|result| result.is_ok())
            .count(),
        3
    );
    assert_eq!(wire.settled.load(Ordering::SeqCst), 3);
    let budget = database
        .community("alpha")
        .unwrap()
        .query(
            "SELECT exposure FROM cvld_payment_budget WHERE id = ?1",
            ["fees"],
        )
        .await
        .unwrap();
    assert_eq!(budget[0].get_i64(0).unwrap(), 12);
}
