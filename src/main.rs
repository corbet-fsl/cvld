use cvld::{
    api, cli,
    config::{CommunityConfig, Config, RootCommunityConfig},
    error::{Error, Result},
    service::{Door, SystemClock},
};
use rmcp::ServiceExt;
use std::{
    future::IntoFuture,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

#[path = "main/root_issuer.rs"]
mod root_issuer;
#[path = "main/signals.rs"]
mod signals;

enum ServeConfig {
    Global(Box<Config>),
    Community(Box<CommunityConfig>),
    Root(Box<RootCommunityConfig>),
}

fn main() {
    if let Err(error) = start_runtime() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn start_runtime() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().map_err(Error::Unavailable.redact())?;
    let deadline = Arc::new(OnceLock::new());
    let result = runtime.block_on(run(deadline.clone()));
    finish_runtime(runtime, result, deadline.as_ref())
}
fn finish_runtime(
    runtime: tokio::runtime::Runtime,
    result: Result<()>,
    deadline: &OnceLock<Instant>,
) -> Result<()> {
    // Aborting an async task does not stop spawn_blocking. Runtime shutdown uses
    // only the remainder of the same signal-started monotonic budget.
    let remaining = deadline.get().map_or(Duration::ZERO, |until| {
        until.saturating_duration_since(Instant::now())
    });
    runtime.shutdown_timeout(remaining);
    if deadline.get().is_some_and(|until| Instant::now() >= *until) {
        return Err(Error::Unavailable);
    }
    result
}

async fn run(deadline: Arc<OnceLock<Instant>>) -> Result<()> {
    let matches = match cli::command().try_get_matches() {
        Ok(matches) => matches,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            print!("{error}");
            return Ok(());
        }
        // Clap's ordinary diagnostics can repeat values from the command line.
        Err(_) => return Err(Error::Invalid),
    };
    execute(matches, deadline).await
}

async fn execute(matches: clap::ArgMatches, deadline: Arc<OnceLock<Instant>>) -> Result<()> {
    let (name, args) = matches.subcommand().ok_or(Error::Invalid)?;
    match name {
        "openapi" => println!("{}", api::openapi_json()),
        "serve" => {
            let (scope, args) = args.subcommand().ok_or(Error::Invalid)?;
            let path = args.get_one::<String>("config").ok_or(Error::Invalid)?;
            if scope == "root-issuer" {
                return root_issuer::run(path, deadline).await;
            }
            // Read the operator's explicit budget before installing the one
            // signal owner; no factory or native verification has started yet.
            let (listen, shutdown_budget, selected) = match scope {
                "global" => {
                    let config = Config::read(path)?;
                    (
                        config.listen.clone(),
                        config.shutdown_budget()?,
                        ServeConfig::Global(Box::new(config)),
                    )
                }
                "community" => {
                    let config = CommunityConfig::read(path)?;
                    (
                        config.listen.clone(),
                        config.shutdown_budget()?,
                        ServeConfig::Community(Box::new(config)),
                    )
                }
                "root-board" => {
                    let config = RootCommunityConfig::read(path)?;
                    (
                        config.listen().to_owned(),
                        config.shutdown_budget()?,
                        ServeConfig::Root(Box::new(config)),
                    )
                }
                _ => return Err(Error::Invalid),
            };
            let signals = signals::Signals::install(shutdown_budget, deadline.clone()).await?;
            let construction = cvld::service::NativeConstruction::new();
            let mut startup_signal = signals.receiver();
            let opening = async {
                match selected {
                    ServeConfig::Global(config) => {
                        Door::global(*config, Arc::new(SystemClock)).await
                    }
                    ServeConfig::Community(config) => {
                        Door::community_with_construction(
                            *config,
                            Arc::new(SystemClock),
                            construction.clone(),
                        )
                        .await
                    }
                    ServeConfig::Root(config) => {
                        Door::root_board_with_construction(
                            *config,
                            Arc::new(SystemClock),
                            construction.clone(),
                        )
                        .await
                    }
                }
            };
            let door = match signals::open(opening, &mut startup_signal).await {
                Ok(Some(door)) => door,
                Ok(None) => return construction.shutdown().await,
                Err(error) => {
                    construction.shutdown().await?;
                    return Err(error);
                }
            };
            let lifecycle = door.clone();
            let maintenance = door.clone();
            let task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    // A failed refresh leaves the old signed expiry intact; consumers fail closed.
                    let _ = maintenance.maintain().await;
                }
            });
            // Even listener/signal setup failures must join the installed
            // native owner while its CRLT async runtime is still available.
            let result = async {
                let listener = tokio::net::TcpListener::bind(listen)
                    .await
                    .map_err(Error::Unavailable.redact())?;
                let mut graceful_signal = signals.receiver();
                let mut stopped = signals.receiver();
                let server = axum::serve(listener, api::router(door))
                    .with_graceful_shutdown(async move {
                        let _ = signals::wait(&mut graceful_signal).await;
                    })
                    .into_future();
                tokio::pin!(server);
                tokio::select! {
                    result = &mut server => result.map_err(Error::Unavailable.redact()),
                    until = signals::wait(&mut stopped) => {
                        task.abort();
                        let until = until?;
                        // Stop native intake immediately while HTTP drains. The
                        // single native owner must be reaped before runtime teardown,
                        // even if the HTTP deadline has already been exhausted.
                        let (drained, joined) = tokio::join!(
                            tokio::time::timeout_at(tokio::time::Instant::from_std(until), &mut server),
                            lifecycle.shutdown_accounts(),
                        );
                        joined?;
                        drained.map_err(Error::Unavailable.redact())?
                            .map_err(Error::Unavailable.redact())
                    },
                }
            }
            .await;
            task.abort();
            let accounts = lifecycle.shutdown_accounts().await;
            let built = construction.shutdown().await;
            accounts?;
            built?;
            result?;
        }
        _ => {
            let token = matches
                .get_one::<String>("session-file")
                .map(|p| std::fs::read_to_string(p).map_err(Error::Unavailable.redact()))
                .transpose()?
                .map(|s| s.trim().to_owned());
            let client = cli::Client::new(
                matches
                    .get_one::<String>("url")
                    .ok_or(Error::Invalid)?
                    .clone(),
                matches
                    .get_one::<String>("host")
                    .ok_or(Error::Invalid)?
                    .clone(),
                token,
            )?;
            if name == "mcp" {
                let running = cvld::mcp::Mcp { client }
                    .serve(cvld::mcp::stdio())
                    .await
                    .map_err(Error::Unavailable.redact())?;
                running
                    .waiting()
                    .await
                    .map_err(Error::Unavailable.redact())?;
            } else {
                let request =
                    serde_json::from_str(args.get_one::<String>("request").ok_or(Error::Invalid)?)
                        .map_err(Error::Invalid.redact())?;
                println!("{}", client.call(name, request).await?);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "main/tests.rs"]
mod tests;
