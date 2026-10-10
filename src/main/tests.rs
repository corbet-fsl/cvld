use super::*;

#[tokio::test]
async fn execution_refuses_an_incomplete_or_extended_command_tree() {
    let matches = cli::command()
        .subcommand_required(false)
        .try_get_matches_from(["cvld"])
        .unwrap();
    assert!(matches!(
        execute(matches, Arc::new(OnceLock::new())).await,
        Err(Error::Invalid)
    ));
    let mut command = cli::command();
    let serve = command.find_subcommand_mut("serve").unwrap();
    *serve = serve
        .clone()
        .subcommand(clap::Command::new("unknown").arg(clap::Arg::new("config").long("config")));
    let matches = command
        .try_get_matches_from(["cvld", "serve", "unknown", "--config", "never-read"])
        .unwrap();
    assert!(matches!(
        execute(matches, Arc::new(OnceLock::new())).await,
        Err(Error::Invalid)
    ));
}

#[test]
fn blocking_runtime_shutdown_uses_only_the_remaining_signal_budget() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release, blocked) = std::sync::mpsc::channel::<()>();
    runtime.spawn_blocking(move || {
        started_tx.send(()).unwrap();
        let _ = blocked.recv();
    });
    started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let deadline = OnceLock::new();
    deadline
        .set(Instant::now() + Duration::from_secs(10))
        .unwrap();
    // HTTP draining has already used most of the operator's total budget.
    std::thread::sleep(Duration::from_secs(8));
    let begun = Instant::now();
    let result = finish_runtime(runtime, Ok(()), &deadline);
    let elapsed = begun.elapsed();
    release.send(()).unwrap();
    assert!(matches!(result, Err(Error::Unavailable)));
    // Two seconds remain; allow five seconds of scheduling slack. Resetting
    // the full ten-second budget still fails this discriminator.
    assert!(elapsed < Duration::from_secs(7));
}
