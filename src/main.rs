use cvld::{
    api, cli,
    config::{CommunityConfig, Config},
    error::{Error, Result},
    service::{Door, SystemClock},
};
use rmcp::ServiceExt;
use std::{
    future::IntoFuture,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

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
            let (listen, shutdown_budget, door) = match scope {
                "global" => {
                    let config = Config::read(path)?;
                    (
                        config.listen.clone(),
                        config.shutdown_budget()?,
                        Door::global(config, Arc::new(SystemClock)).await?,
                    )
                }
                "community" => {
                    let config = CommunityConfig::read(path)?;
                    (
                        config.listen.clone(),
                        config.shutdown_budget()?,
                        Door::community(config, Arc::new(SystemClock)).await?,
                    )
                }
                _ => return Err(Error::Invalid),
            };
            let maintenance = door.clone();
            let task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    // A failed refresh leaves the old signed expiry intact; consumers fail closed.
                    let _ = maintenance.maintain().await;
                }
            });
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .map_err(Error::Unavailable.redact())?;
            #[cfg(unix)]
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(Error::Unavailable.redact())?;
            let (shutdown, stopped) = tokio::sync::oneshot::channel();
            let server = axum::serve(listener, api::router(door))
                .with_graceful_shutdown(async move {
                    #[cfg(unix)]
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {},
                        _ = terminate.recv() => {},
                    }
                    #[cfg(not(unix))]
                    let _ = tokio::signal::ctrl_c().await;
                    let began = Instant::now();
                    let until = began.checked_add(shutdown_budget).unwrap_or(began);
                    let _ = deadline.set(until);
                    let _ = shutdown.send(until);
                })
                .into_future();
            tokio::pin!(server);
            let result = tokio::select! {
                result = &mut server => result.map_err(Error::Unavailable.redact()),
                until = stopped => {
                    task.abort();
                    let until = until.map_err(Error::Unavailable.redact())?;
                    // An unfinished mutation has an uncertain result after this bound.
                    tokio::time::timeout_at(tokio::time::Instant::from_std(until), &mut server)
                        .await
                        .map_err(Error::Unavailable.redact())?
                        .map_err(Error::Unavailable.redact())
                },
            };
            task.abort();
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
                    .serve(rmcp::transport::stdio())
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
