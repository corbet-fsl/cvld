#![cfg(feature = "development-gate")]
mod support;

use cvld::{
    client::{Client, HttpClient, action, contract},
    error::Error,
};
use serde_json::json;
use support::*;

#[tokio::test(flavor = "multi_thread")]
async fn generated_client_forwards_real_public_member_and_root_calls() {
    let service = global(100).await;
    let mut public =
        Client::new(HttpClient::new(service.base.clone(), WALLET.into(), None).unwrap());
    let metadata = action("global_public").unwrap();
    assert_eq!(metadata.path(), "/v1/global_public");
    assert_eq!(metadata.schema()["x-role"], "public");
    assert_eq!(contract()["info"]["title"], "cvld");
    assert!(public.call("global_public", json!({})).await.unwrap()["issuer"].is_array());
    assert!(matches!(
        public.call("passport_challenge", json!({})).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        public.call("../global_public", json!({})).await,
        Err(Error::Invalid)
    ));
    assert!(action("").is_none());
    let member = enrol(&service, WALLET, None).await;
    let member_user = member.user.clone();
    client(&service, WALLET, Some(&member.session))
        .call("development_gate", json!({}))
        .await
        .unwrap();
    let mut member = Client::new(
        HttpClient::new(service.base.clone(), WALLET.into(), Some(member.session)).unwrap(),
    );
    assert!(member.call("passport_challenge", json!({})).await.is_ok());
    assert!(matches!(
        member
            .call("global_suspend", json!({"user":"wrong","until":NOW + 1}))
            .await,
        Err(Error::Forbidden)
    ));
    let root = enrol(
        &service,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    let mut root = Client::new(
        HttpClient::new(service.base.clone(), ROOT.into(), Some(root.session)).unwrap(),
    );
    root.call("global_warn", json!({"user": member_user}))
        .await
        .unwrap();
    root.call(
        "global_suspend",
        json!({"user": member_user, "until": (NOW / 86_400 + 1) * 86_400}),
    )
    .await
    .unwrap();
    assert!(member.call("passport_challenge", json!({})).await.is_err());
    root.call("logout", json!({})).await.unwrap();
    assert!(matches!(
        root.call("logout", json!({})).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        HttpClient::new(
            "https://wallet.example.test".into(),
            "wrong.example.test".into(),
            None
        ),
        Err(Error::WrongHost)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_logout_with_a_lost_or_malformed_response_is_unknown_and_never_retried() {
    use axum::{Router, routing::post};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let service = global(100).await;
    let mut root = enrol(
        &service,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    for mode in 0..10 {
        let session = login(
            &service,
            ROOT,
            &mut root.authenticator,
            &root.user,
            &root.credential,
        )
        .await;
        let upstream = client(&service, ROOT, Some(&session));
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let router = Router::new().route(
            "/v1/logout",
            post(move || {
                let upstream = upstream.clone();
                let observed = observed.clone();
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    upstream.call("logout", json!({})).await.unwrap();
                    support::client_faults::corrupted_response(mode)
                }
            }),
        );
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", socket.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(socket, router).await.unwrap() });
        let proxy = HttpClient::new(base, ROOT.into(), Some(session.clone())).unwrap();
        assert!(matches!(
            proxy.call("logout", json!({})).await,
            Err(Error::Reconcile)
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            client(&service, ROOT, Some(&session))
                .call("logout", json!({}))
                .await,
            Err(Error::Unauthorized)
        ));
        task.abort();
    }
}
