use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_simulation_has_no_config_credentials_or_payment_fact_and_unknown_stops() {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let member = enrol_community(&service, HOST, &passport).await;
    let api = client(&service, HOST, Some(&member.session));
    assert_ne!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "payment_offer",
            json!({})
        )
        .await,
        200
    );
    let result=api.call("payment_simulate",json!({"dummy_offer":payment_support::offer(),"dummy_payload":payment_support::payload(),"access":{"level":"explicit-dummy-level","starts_at":NOW,"expires_at":NOW+86400},"maximum":payment_support::amount(4),"actual_fee":null,"budget":payment_support::amount(12),"source":"explicit hypothetical tariff","expires_at":NOW+60,"outcome":"uncertain","satisfies_terms":false})).await.unwrap();
    assert_eq!(result["simulated"], true);
    assert_eq!(result["outcome"], "uncertain");
    assert!(result["access"].is_null());
    assert!(result.get("operation").is_none());
    assert_ne!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "payment_accept",
            json!({"operation":"simulation"})
        )
        .await,
        200
    );
}
