//! Ownership and original native cancellation; no accepting service is built.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

fn retained(
    group: &NativeConstruction,
    build: impl FnOnce(&Cancellation) -> Result<Parts> + Send + 'static,
) -> Arc<Task> {
    let task = Task::start(build).unwrap();
    group.0.0.lock().unwrap().tasks.push(task.clone());
    task
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_before_registration_withdraws_the_late_owner_and_joins() {
    let group = NativeConstruction::new();
    let withdrew = Arc::new(AtomicBool::new(false));
    let owner = withdrew.clone();
    let (release, waiting) = std::sync::mpsc::channel();
    let (entered, started) = tokio::sync::oneshot::channel();
    let task = retained(&group, move |cancellation| {
        entered.send(()).unwrap();
        waiting.recv().unwrap();
        cancellation.register(move || owner.store(true, Ordering::SeqCst));
        assert!(cancellation.check().is_err());
        Err(Error::Invalid)
    });
    started.await.unwrap();
    let ending = group.clone();
    let join = tokio::spawn(async move { ending.shutdown().await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while task.cancellation.check().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    release.send(()).unwrap();
    join.await.unwrap().unwrap();
    assert!(withdrew.load(Ordering::SeqCst));
    assert!(matches!(*task.phase.borrow(), Completion::Joined(true)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoning_a_shutdown_waiter_keeps_the_actual_build_and_join_owned() {
    use std::{future::Future, task::Poll};
    let group = NativeConstruction::new();
    let finished = Arc::new(AtomicBool::new(false));
    let completion = finished.clone();
    let (release, waiting) = std::sync::mpsc::channel();
    let (entered, started) = tokio::sync::oneshot::channel();
    let task = retained(&group, move |_| {
        entered.send(()).unwrap();
        waiting.recv().unwrap();
        completion.store(true, Ordering::SeqCst);
        Err(Error::Invalid)
    });
    started.await.unwrap();
    let mut shutdown = Box::pin(group.shutdown());
    std::future::poll_fn(|cx| {
        assert!(matches!(shutdown.as_mut().poll(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    drop(shutdown);
    assert!(!finished.load(Ordering::SeqCst));
    release.send(()).unwrap();
    group.shutdown().await.unwrap();
    assert!(finished.load(Ordering::SeqCst));
    assert!(matches!(*task.phase.borrow(), Completion::Joined(true)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_construction_error_is_returned_only_after_its_worker_is_joined() {
    let task = Task::start(|_| Err(Error::Invalid)).unwrap();
    assert!(matches!(task.result().await, Err(Error::Invalid)));
    task.shutdown().await.unwrap();
    assert!(matches!(*task.phase.borrow(), Completion::Joined(true)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicked_builder_returns_unavailable_without_stranding_its_join() {
    let task = Task::start(|_| panic!("fictional constructor panic")).unwrap();
    assert!(matches!(task.result().await, Err(Error::Unavailable)));
    task.shutdown().await.unwrap();
    assert!(matches!(*task.phase.borrow(), Completion::Joined(true)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shared_group_withdraws_every_builder_before_waiting_for_any_join() {
    let group = NativeConstruction::new();
    let (cancel_first, first_cancelled) = std::sync::mpsc::channel();
    let (cancel_second, second_cancelled) = std::sync::mpsc::channel();
    let (first_entered, first_started) = tokio::sync::oneshot::channel();
    let (second_entered, second_started) = tokio::sync::oneshot::channel();
    let first = retained(&group, move |cancellation| {
        cancellation.register(move || {
            let _ = cancel_first.send(());
        });
        first_entered.send(()).unwrap();
        // This real owner thread cannot finish until the other owner's cancel.
        second_cancelled.recv().unwrap();
        Err(Error::Unavailable)
    });
    let second = retained(&group, move |cancellation| {
        cancellation.register(move || {
            let _ = cancel_second.send(());
        });
        second_entered.send(()).unwrap();
        first_cancelled.recv().unwrap();
        Err(Error::Unavailable)
    });
    first_started.await.unwrap();
    second_started.await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), group.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(*first.phase.borrow(), Completion::Joined(true)));
    assert!(matches!(*second.phase.borrow(), Completion::Joined(true)));
    assert!(group.0.0.lock().unwrap().closed);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_the_original_native_child_and_joins_before_returning() {
    use std::{os::unix::fs::PermissionsExt, time::Duration};
    let sleep = std::env::split_paths(&std::env::var_os("PATH").expect("test host PATH"))
        .map(|directory| directory.join("sleep"))
        .find(|path| {
            path.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .and_then(|path| path.canonicalize().ok())
        .expect("test host must provide sleep");
    // Resolve before CVFY clears the child's environment. Quote the actual
    // absolute host path; neither Nix's layout nor /bin/sleep is assumed.
    let sleep = format!("'{}'", sleep.to_str().unwrap().replace('\'', "'\\''"));
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("refusing-native-child");
    let receipt = directory.path().join("started");
    // A refusal-only transport fixture: exec preserves the owned PID, emits no
    // verdict, and never claims these metadata bytes are a circuit/proof.
    std::fs::write(
        &executable,
        format!("#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$0.started\"\nexec {sleep} 60\n"),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let receipt_path = executable.with_file_name("refusing-native-child.started");
    let verifier = cvfy::NativeVerifier::new(cvfy::NativeVerifierConfig {
        executable,
        scope: czkp::ProofScope {
            circuit_digest: [1; 32],
            // SHA-256 of the fixed public metadata key [5; 32].
            verifying_key_digest: [
                248, 73, 214, 115, 37, 250, 207, 4, 23, 123, 198, 99, 178, 220, 84, 64, 81, 131,
                28, 88, 158, 245, 129, 212, 18, 242, 235, 164, 72, 52, 231, 124,
            ],
        },
        timeout: Duration::from_secs(60),
        maximum_parallel: 1,
        max_proof_bytes: 32,
        max_public_inputs: 1,
        threads: 1,
        memory_megabytes: 256,
        verification_key: vec![5; 32],
        srs_g1: vec![0; czkp::native::SRS_G1_BYTES],
        srs_g2: [0; 128],
    })
    .unwrap();
    let group = NativeConstruction::new();
    let owner = verifier.clone();
    let task = retained(&group, move |cancellation| {
        let cancel = owner.cancellation();
        cancellation.register(move || cancel.cancel());
        assert_eq!(
            owner.verify(&[[0; 32]], &[0; 32]),
            Err(czkp::Error::CryptoProvider)
        );
        Err(Error::Unavailable)
    });
    let pid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(pid) = std::fs::read_to_string(&receipt_path)
                .ok()
                .filter(|text| text.ends_with('\n'))
                .and_then(|text| text.trim().parse::<u32>().ok())
                .filter(|pid| *pid > 0)
            {
                break pid;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let began = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(5), group.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(began.elapsed() < Duration::from_secs(5));
    assert!(matches!(*task.phase.borrow(), Completion::Joined(true)));
    #[cfg(target_os = "linux")]
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "owned child must be reaped"
    );
    #[cfg(not(target_os = "linux"))]
    assert!(pid > 0);
    std::fs::rename(&receipt_path, &receipt).unwrap();
    assert_eq!(
        verifier.verify(&[[0; 32]], &[0; 32]),
        Err(czkp::Error::CryptoProvider)
    );
    assert!(
        !receipt_path.exists(),
        "withdrawn verifier must not spawn again"
    );
}
