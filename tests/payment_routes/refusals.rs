use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_policy_disabled_cost_limits_wrong_owner_and_stale_consent_refuse_without_io() {
    let global = global(200).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let wire = Wire::new(Reply::Success);
    let service = configured(
        &public,
        payments::transport::AnyTransport(Arc::new(Inert(wire.clone()))),
        false,
    )
    .await;
    let member = enrol_community(&service, HOST, &passport).await;
    assert_ne!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "payment_plan",
            plan()
        )
        .await,
        200
    );
    assert_eq!(wire.supported.load(Ordering::SeqCst), 0);
    let wire = Wire::new(Reply::Success);
    let service = configured(
        &public,
        payments::transport::AnyTransport(Arc::new(Inert(wire.clone()))),
        true,
    )
    .await;
    let member = enrol_community(&service, HOST, &passport).await;
    let api = client(&service, HOST, Some(&member.session));
    let mut too_large = plan();
    too_large["budget"]["atoms"] = json!(13);
    assert_ne!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "payment_plan",
            too_large
        )
        .await,
        200
    );
    let prepared = api.call("payment_plan", plan()).await.unwrap();
    assert_ne!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "payment_execute",
            json!({"operation":prepared["operation"],"authorization":"wrong"})
        )
        .await,
        200
    );
    assert_ne!(
        call_status(
            &service,
            "api.admin.alpha.example.test",
            Some(&member.session),
            "payment_execute",
            json!({"operation":prepared["operation"],"authorization":prepared["authorization"]})
        )
        .await,
        200
    );
    service.clock.set(prepared["expires_at"].as_u64().unwrap());
    assert_ne!(
        call_status(
            &service,
            HOST,
            Some(&member.session),
            "payment_execute",
            json!({"operation":prepared["operation"],"authorization":prepared["authorization"]})
        )
        .await,
        200
    );
    assert_eq!(wire.supported.load(Ordering::SeqCst), 0);
}
