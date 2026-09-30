use cvld::{
    api, cli,
    config::{CommunityConfig, Config},
    error::{Error, Result},
    service::{Door, SystemClock},
};
use rmcp::ServiceExt;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
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
    let (name, args) = matches.subcommand().ok_or(Error::Invalid)?;
    match name {
        "openapi" => println!("{}", api::openapi_json()),
        "serve" => {
            let (scope, args) = args.subcommand().ok_or(Error::Invalid)?;
            let path = args.get_one::<String>("config").ok_or(Error::Invalid)?;
            let (listen, door) = match scope {
                "global" => {
                    let config = Config::read(path)?;
                    (
                        config.listen.clone(),
                        Door::global(config, Arc::new(SystemClock)).await?,
                    )
                }
                "community" => {
                    let config = CommunityConfig::read(path)?;
                    (
                        config.listen.clone(),
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
                .map_err(|_| Error::Unavailable)?;
            axum::serve(listener, api::router(door))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
                .map_err(|_| Error::Unavailable)?;
            task.abort();
        }
        _ => {
            let token = matches
                .get_one::<String>("session-file")
                .map(|p| std::fs::read_to_string(p).map_err(|_| Error::Unavailable))
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
                    .map_err(|_| Error::Unavailable)?;
                running.waiting().await.map_err(|_| Error::Unavailable)?;
            } else {
                let request =
                    serde_json::from_str(args.get_one::<String>("request").ok_or(Error::Invalid)?)
                        .map_err(|_| Error::Invalid)?;
                println!("{}", client.call(name, request).await?);
            }
        }
    }
    Ok(())
}
