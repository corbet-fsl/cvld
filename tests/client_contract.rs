#![cfg(feature = "development-gate")]
mod support;

use cvld::api::Ceremony;
use cvld::{
    client::{Client, HttpClient, action, contract},
    error::Error,
};
use serde_json::{Value, json};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};
#[path = "support/client_faults.rs"]
mod client_faults;
use support::*;

async fn login_request(
    service: &Running,
    host: &str,
    authenticator: &mut SoftToken,
    user: &str,
    credential: &[u8],
) -> Value {
    let client = client(service, host, None);
    let start: Ceremony = serde_json::from_value(
        client
            .call("login_begin", json!({"user":user,"credential":credential}))
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge: ckyh::RequestChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = authenticator
        .perform_auth(
            ckyh::Url::parse(&format!("https://{host}")).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    json!({"ceremony":start.ceremony,"credential":credential})
}
#[tokio::test(flavor = "multi_thread")]
async fn schema_valid_duplicate_response_keys_are_refused_on_the_real_wire() {
    use axum::{Router, routing::post};
    let service = global(100).await;
    let upstream = client(&service, WALLET, None);
    let router = Router::new().route(
        "/v1/global_public",
        post(move || {
            let upstream = upstream.clone();
            async move {
                let value = upstream.call("global_public", json!({})).await.unwrap();
                client_faults::duplicate_public_response(&value)
            }
        }),
    );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", socket.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(socket, router).await.unwrap() });
    let proxy = HttpClient::new(base, WALLET.into(), None).unwrap();
    assert!(matches!(
        proxy.call("global_public", json!({})).await,
        Err(Error::Reconcile)
    ));
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn authentication_adopts_the_real_session_without_exporting_its_bearer() {
    let service = global(100).await;
    let mut member = enrol(&service, WALLET, None).await;
    let request = login_request(
        &service,
        WALLET,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    let mut api = Client::new(client(&service, WALLET, None));
    assert!(cvld::client::forwarding_action("login_finish").is_none());
    assert!(cvld::client::forwarding_action("global_public").is_some());
    assert!(cvld::client::forwarding_action("unknown").is_none());
    assert!(cvld::client::forwarding_contract()["paths"]["/v1/login_finish"].is_null());
    assert!(matches!(
        api.forward("login_finish", request.clone()).await,
        Err(Error::Invalid)
    ));
    let mut foreign = Client::new(client(&service, ROOT, None));
    assert!(matches!(
        foreign.authenticate(request.clone()).await,
        Err(Error::Unauthorized)
    ));
    let info = api.authenticate(request.clone()).await.unwrap();
    assert_eq!(info.user, member.user);
    assert_eq!(info.role, "member");
    assert!(info.expires > NOW);
    let safe = serde_json::to_value(&info).unwrap();
    assert!(safe.get("token").is_none());
    assert_eq!(safe.as_object().unwrap().len(), 3);
    assert!(matches!(
        api.authenticate(request).await,
        Err(Error::Unauthorized)
    ));
    api.forward("logout", json!({})).await.unwrap();
    assert!(matches!(
        api.forward("logout", json!({})).await,
        Err(Error::Unauthorized)
    ));
}

#[test]
fn portable_action_lookup_preserves_every_generated_path_and_schema() {
    let paths = contract()["paths"].as_object().unwrap();
    assert_eq!(paths.len(), cvld::api::ACTIONS.len());
    for owner in cvld::api::ACTIONS {
        let metadata = action(owner.name).unwrap();
        assert_eq!(metadata.path(), format!("/v1/{}", owner.name));
        assert_eq!(metadata.schema(), &paths[metadata.path()]["post"]);
        assert_eq!(metadata.schema()["operationId"], owner.name);
    }
    for unknown in ["", "global_public/", "../global_public", "not_an_action"] {
        assert!(action(unknown).is_none());
    }
}

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
    use axum::{Router, body::Body, response::Response, routing::post};
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
    for mode in (0..10).chain(11..13) {
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
        let router =
            Router::new().route(
                "/v1/logout",
                post(move || {
                    let upstream = upstream.clone();
                    let observed = observed.clone();
                    async move {
                        observed.fetch_add(1, Ordering::SeqCst);
                        upstream.call("logout", json!({})).await.unwrap();
                        match mode {
                            0 => Response::new(Body::from("{")),
                            1 => Response::builder()
                                .status(403)
                                .body(Body::from("{\"error\":\"unavailable\"}"))
                                .unwrap(),
                            2 => Response::new(Body::from("null")),
                            3 => Response::builder()
                                .status(302)
                                .header("location", "/v1/logout")
                                .body(Body::empty())
                                .unwrap(),
                            4 => Response::new(Body::from("{\"error\":\"unauthorized\"}")),
                            5 => Response::builder()
                                .header("content-length", 17 * 1024 * 1024)
                                .body(Body::empty())
                                .unwrap(),
                            6 => Response::new(Body::from_stream(futures_util::stream::iter([
                                Ok(axum::body::Bytes::from_static(b"{")),
                                Err(std::io::Error::other("synthetic truncated response")),
                            ]))),
                            7 => Response::new(Body::from_stream(futures_util::stream::iter([
                                Ok::<_, std::io::Error>(vec![b' '; 17 * 1024 * 1024]),
                            ]))),
                            8 => Response::new(Body::from("{\"unexpected\":true}")),
                            11 | 12 => client_faults::corrupted_response(mode),
                            _ => Response::new(Body::from("{\"issuer\":[]}")),
                        }
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
