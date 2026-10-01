//! Real native door behind the ephemeral browser-test TLS endpoint.
#[path = "mod.rs"]
mod support;
use axum::{
    Json, Router,
    body::Body,
    http::HeaderMap,
    response::Response,
    routing::{get, post},
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use support::*;

#[tokio::main]
async fn main() {
    let path = std::env::args().nth(1).expect("fixture output path");
    let service = global(200).await;
    let mut member = enrol(&service, WALLET, None).await;
    client(&service, WALLET, Some(&member.session))
        .call("development_gate", json!({}))
        .await
        .unwrap();
    let mut sessions = Vec::new();
    for _ in 0..11 {
        sessions.push(
            login(
                &service,
                WALLET,
                &mut member.authenticator,
                &member.user,
                &member.credential,
            )
            .await,
        );
    }
    let cases = Arc::new(
        sessions
            .iter()
            .map(|session| (session.clone(), AtomicUsize::new(0)))
            .collect::<Vec<_>>(),
    );
    let stats = cases.clone();
    let upstream = service.base.clone();
    let router = Router::new()
        .route(
            "/__faults",
            get(move || {
                let stats = stats.clone();
                async move {
                    Json(
                        stats
                            .iter()
                            .map(|(_, count)| count.load(Ordering::SeqCst))
                            .collect::<Vec<_>>(),
                    )
                }
            }),
        )
        .route(
            "/v1/logout",
            post(move |headers: HeaderMap, body: axum::body::Bytes| {
                let cases = cases.clone();
                let upstream = upstream.clone();
                async move {
                    let token = headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok());
                    let selected = token
                        .and_then(|value| value.strip_prefix("Bearer "))
                        .and_then(|token| cases.iter().position(|(session, _)| session == token));
                    if let Some(index) = selected {
                        cases[index].1.fetch_add(1, Ordering::SeqCst);
                    }
                    // The original door verifies and commits first. Only its wire reply
                    // is corrupted, using the same cases as the native client tests.
                    let mut request = reqwest::Client::new()
                        .post(format!("{upstream}/v1/logout"))
                        .header("host", WALLET)
                        .header("content-type", "application/json")
                        .body(body);
                    if let Some(token) = token {
                        request = request.header("authorization", token);
                    }
                    let response = request.send().await.unwrap();
                    let status = response.status();
                    let bytes = response.bytes().await.unwrap();
                    if let Some(index) = selected {
                        assert_eq!(status, reqwest::StatusCode::OK);
                        support::client_faults::corrupted_response(index)
                    } else {
                        Response::builder()
                            .status(status.as_u16())
                            .body(Body::from(bytes))
                            .unwrap()
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let faults = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let data = json!({ "upstream": service.base, "faults": faults, "session": member.session, "fault_sessions": sessions });
    let temporary = format!("{path}.pending");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).unwrap();
    serde_json::to_writer(&mut file, &data).unwrap();
    drop(file);
    // The runner sees only the complete private fixture, never a partial write.
    std::fs::rename(&temporary, &path).unwrap();
    tokio::signal::ctrl_c().await.unwrap();
    task.abort();
}
