//! Shared startup/serving signal boundary; no native proof verdict is supplied.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

struct OpeningOwner(Arc<AtomicBool>);
impl Drop for OpeningOwner {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn startup_signal_drops_the_actual_opening_and_preserves_the_same_deadline() {
    let dropped = Arc::new(AtomicBool::new(false));
    let owned = dropped.clone();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (signal, mut startup) = watch::channel(None);
    let mut running = startup.clone();
    let until = Instant::now() + Duration::from_secs(10);
    let send = tokio::spawn(async move {
        started.await.unwrap();
        signal.send_replace(Some(until));
    });
    let result = open(
        async move {
            let _owner = OpeningOwner(owned);
            entered.send(()).unwrap();
            std::future::pending::<Result<()>>().await
        },
        &mut startup,
    )
    .await
    .unwrap();
    send.await.unwrap();
    assert!(result.is_none());
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(wait(&mut running).await.unwrap(), until);
    assert_eq!(wait(&mut startup).await.unwrap(), until);
}

#[tokio::test]
async fn a_signal_already_observed_before_factory_poll_prevents_opening() {
    let polled = Arc::new(AtomicBool::new(false));
    let owner = polled.clone();
    let until = Instant::now();
    let (_signal, mut receiver) = watch::channel(Some(until));
    let result = open(
        async move {
            owner.store(true, Ordering::SeqCst);
            Ok(())
        },
        &mut receiver,
    )
    .await
    .unwrap();
    assert!(result.is_none());
    assert!(!polled.load(Ordering::SeqCst));
    assert_eq!(wait(&mut receiver).await.unwrap(), until);
}

#[tokio::test]
async fn completed_or_failed_opening_keeps_the_original_result() {
    let (_signal, mut receiver) = watch::channel(None);
    assert_eq!(open(async { Ok(7) }, &mut receiver).await.unwrap(), Some(7));
    assert!(matches!(
        open::<()>(async { Err(Error::Invalid) }, &mut receiver).await,
        Err(Error::Invalid)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn the_installed_sigterm_owner_cancels_startup_before_a_door_exists() {
    let deadline = Arc::new(OnceLock::new());
    let signals = Signals::install(Duration::from_secs(10), deadline.clone())
        .await
        .unwrap();
    let mut startup = signals.receiver();
    let mut serving = signals.receiver();
    let dropped = Arc::new(AtomicBool::new(false));
    let owned = dropped.clone();
    let (entered, started) = tokio::sync::oneshot::channel();
    let signal = tokio::spawn(async move {
        started.await.unwrap();
        // Send only to this test executable, after its real Tokio SIGTERM
        // handler is installed and the opening owner has been polled.
        assert!(
            tokio::process::Command::new("kill")
                .args(["-TERM", &std::process::id().to_string()])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .unwrap()
                .success()
        );
    });
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        open(
            async move {
                let _owner = OpeningOwner(owned);
                entered.send(()).unwrap();
                std::future::pending::<Result<()>>().await
            },
            &mut startup,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    signal.await.unwrap();
    assert!(result.is_none());
    assert!(dropped.load(Ordering::SeqCst));
    let original = *deadline.get().unwrap();
    assert_eq!(wait(&mut serving).await.unwrap(), original);
    assert_eq!(wait(&mut startup).await.unwrap(), original);
    assert!(original > Instant::now());
}
