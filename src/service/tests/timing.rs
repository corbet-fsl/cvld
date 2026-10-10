use super::*;
use std::{future::Future, task::Poll};

struct ScriptClock {
    base: Arc<TestClock>,
    samples: std::sync::Mutex<std::collections::VecDeque<u64>>,
    calls: std::sync::atomic::AtomicUsize,
    notify_at: std::sync::atomic::AtomicUsize,
    observed: tokio::sync::Notify,
}
impl Clock for ScriptClock {
    fn now(&self) -> u64 {
        let now = self
            .samples
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| self.base.now());
        let count = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if count == self.notify_at.load(std::sync::atomic::Ordering::SeqCst) {
            self.observed.notify_one();
        }
        now
    }
}

async fn scripted_global() -> (Running, Arc<ScriptClock>) {
    let dir = tempfile::tempdir().unwrap();
    let base = Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)));
    let clock = Arc::new(ScriptClock {
        base: base.clone(),
        samples: Default::default(),
        calls: Default::default(),
        notify_at: std::sync::atomic::AtomicUsize::new(usize::MAX),
        observed: Default::default(),
    });
    let door = Door::global(global_config(dir.path(), 100).await, clock.clone())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let router = crate::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (
        Running {
            base: address,
            door,
            clock: base,
            task,
            dir,
        },
        clock,
    )
}

fn headers(member: &Member) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("host", WALLET.parse().unwrap());
    headers.insert(
        "authorization",
        format!("Bearer {}", member.session).parse().unwrap(),
    );
    headers
}

// Polling once while the actual service mutex is held proves the operation has
// reached the wait. There is no timer-based guess about task scheduling.
async fn blocked<T>(operation: &mut std::pin::Pin<Box<impl Future<Output = T>>>) {
    std::future::poll_fn(|cx| {
        assert!(operation.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execution_rechecks_session_time_after_waiting_for_authentication() {
    for completed_at in [NOW + 600, NOW + 598] {
        let global = global(100).await;
        let member = enrol(&global, WALLET, None).await;
        global.clock.set(NOW + 599);
        let action = action("passport_issue").unwrap();
        let ctx = global
            .door
            .authorize(action, &headers(&member))
            .await
            .unwrap();
        let auth = global.door.auth(WALLET).unwrap();
        let lock = auth.lock().await;
        let mut operation = Box::pin(global.door.complete_context(action, ctx));
        blocked(&mut operation).await;
        global.clock.set(completed_at);
        drop(lock);
        assert!(
            matches!(operation.await, Err(Error::Unauthorized)),
            "waiting for authentication must not preserve an expired or rolled-back session"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execution_rechecks_time_after_the_actual_credential_query() {
    let (global, clock) = scripted_global().await;
    let member = enrol(&global, WALLET, None).await;
    global.clock.set(NOW + 599);
    let action = action("passport_issue").unwrap();
    let ctx = global
        .door
        .authorize(action, &headers(&member))
        .await
        .unwrap();
    // Both pre-query samples are valid; the real credential query completes
    // before the third sample observes the session's exact expiry.
    *clock.samples.lock().unwrap() = [NOW + 599, NOW + 599, NOW + 600].into();
    assert!(matches!(
        global.door.complete_context(action, ctx).await,
        Err(Error::Unauthorized)
    ));
    assert!(clock.samples.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_expiring_during_issuance_cannot_publish_a_usable_passport() {
    for expire in [false, true] {
        let (global, clock) = scripted_global().await;
        let member = enrol(&global, WALLET, None).await;
        let client = client(&global, WALLET, Some(&member.session));
        client
            .call("development_gate", serde_json::json!({}))
            .await
            .unwrap();
        let public: GlobalPublic = serde_json::from_value(
            client
                .call("global_public", serde_json::json!({}))
                .await
                .unwrap(),
        )
        .unwrap();
        let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
        let mut rng = cpsd::rand::rngs::OsRng;
        let secret = cpsd::HolderSecret::generate(&mut rng);
        global.clock.set(NOW + 599);
        let challenge: Bytes = serde_json::from_value(
            client
                .call("passport_challenge", serde_json::json!({}))
                .await
                .unwrap(),
        )
        .unwrap();
        let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
        let (request, pending) =
            cpsd::request_issue(&mut rng, &secret, &issuer, &challenge).unwrap();
        let lock = global.door.global_backend().unwrap().lock().await;
        // The route observes time once at admission, three times while
        // completing authentication, and once before dispatch. Notify on that
        // last observation while the actual backend mutex keeps work pending.
        clock.notify_at.store(
            clock.calls.load(std::sync::atomic::Ordering::SeqCst) + 5,
            std::sync::atomic::Ordering::SeqCst,
        );
        let operation =
            tokio::spawn(async move {
                client.call("passport_issue", serde_json::json!({
                "challenge": challenge.to_bytes().to_vec(), "request": request.to_bytes(),
            })).await
            });
        tokio::time::timeout(Duration::from_secs(10), clock.observed.notified())
            .await
            .unwrap();
        if expire {
            global.clock.set(NOW + 600);
        }
        drop(lock);
        let result = operation
            .await
            .unwrap()
            .map(|value| serde_json::from_value::<Bytes>(value).unwrap());
        if expire {
            if let Ok(response) = result {
                // This proves the old behavior would release a real usable
                // upstream credential, not merely return malformed bytes.
                pending
                    .finish(&cpsd::BlindPassport::from_bytes(&response.bytes).unwrap())
                    .unwrap();
                panic!("an expired session published a usable passport");
            }
            assert!(matches!(result, Err(Error::Reconcile)));
        } else {
            let response = result.unwrap();
            pending
                .finish(&cpsd::BlindPassport::from_bytes(&response.bytes).unwrap())
                .unwrap();
        }
    }
}
