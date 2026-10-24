//! One trusted process links the global service to its explicitly listed communities.
use super::root_issuer::{Service, config::host, lifecycle};
use super::*;
use cvld::service::NativeConstruction;
#[path = "platform/hub.rs"]
mod hub;
use serde::Deserialize;
use std::{collections::BTreeSet, net::SocketAddr};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Files {
    global_config: String,
    community_configs: Vec<String>,
    /// Hosts the root board in this same process; absent means no root board.
    #[serde(default)]
    root_board: Option<RootFiles>,
    /// Multi-tenant hosting: communities are created at runtime and registered.
    #[serde(default)]
    hub: Option<hub::HubFiles>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFiles {
    root_board_config: String,
    purpose_key_file: String,
}

struct Prepared {
    global: Config,
    communities: Vec<CommunityConfig>,
    root: Option<(RootCommunityConfig, cpsd::IssuerKey)>,
    hub: Option<hub::Prepared>,
    budget: Duration,
}

pub(super) async fn run(path: &str, deadline: Arc<OnceLock<Instant>>) -> Result<()> {
    // Parse every explicit component and bind before creating native owners.
    let Prepared {
        global,
        communities,
        root,
        hub,
        budget,
    } = read(path)?;
    let signals = signals::Signals::install(budget, deadline.clone()).await?;
    let construction = NativeConstruction::new();
    let mut services = Vec::new();
    let mut listeners = Vec::new();
    let mut interrupted = signals.receiver();
    let opening = open_components(
        global,
        communities,
        (root, hub),
        Arc::new(SystemClock),
        &construction,
        &mut services,
        &mut listeners,
    );
    match signals::open(opening, &mut interrupted).await {
        Ok(Some(())) => {}
        other => {
            drop(listeners);
            lifecycle::close(&services, &construction).await?;
            return other.map(|_| ());
        }
    }
    lifecycle::serve(
        &services,
        listeners,
        &construction,
        &signals,
        budget,
        deadline,
    )
    .await
}

async fn open_components(
    global: Config,
    communities: Vec<CommunityConfig>,
    (root, hub): (
        Option<(RootCommunityConfig, cpsd::IssuerKey)>,
        Option<hub::Prepared>,
    ),
    clock: Arc<dyn cvld::service::Clock>,
    construction: &NativeConstruction,
    services: &mut Vec<Service>,
    listeners: &mut Vec<tokio::net::TcpListener>,
) -> Result<()> {
    let address = global.listen.clone();
    let (database_url, database_token) = (
        global.database_url.clone(),
        match &global.database_token_file {
            Some(path) => Some(
                String::from_utf8(Config::secret(path)?.to_vec())
                    .map_err(Error::Invalid.redact())?,
            ),
            None => None,
        },
    );
    let base = global.domain.clone();
    let door = Door::global(global, clock.clone()).await?;
    // Retain each completed Door before the next await so abandoned startup
    // still fences and joins every earlier owner.
    services.push(Service::new(address, door));
    for community in communities {
        let address = community.listen.clone();
        let door =
            Door::community_with_construction(community, clock.clone(), construction.clone())
                .await?;
        services.push(Service::new(address, door));
    }
    let mut root_purpose = None;
    if let Some((config, key)) = root {
        let address = config.listen().to_owned();
        let door =
            Door::root_board_with_construction(config, clock.clone(), construction.clone()).await?;
        let communities = services.len();
        services.push(Service::new(address, door));
        let purpose = services[communities].door.root_board_purpose(key).await?;
        root_purpose = Some(purpose.clone());
        // Every hosted community accepts the root board's purpose, as when the
        // root board runs as its own process.
        for service in services.iter().take(communities).skip(1) {
            service
                .door
                .attach_root_board_purpose(purpose.clone())
                .await?;
        }
    }
    if let Some(hub) = hub {
        hub::open(
            hub,
            (&database_url, database_token),
            &base,
            root_purpose,
            clock.clone(),
            construction,
            services,
        )
        .await?;
    }
    // No server is exposed until ALL links validate and ALL binds succeed.
    for service in services.iter() {
        listeners.push(
            tokio::net::TcpListener::bind(&service.address)
                .await
                .map_err(Error::Unavailable.redact())?,
        );
    }
    Ok(())
}

fn read(path: &str) -> Result<Prepared> {
    let files: Files =
        serde_json::from_slice(&std::fs::read(path).map_err(Error::Unavailable.redact())?)
            .map_err(Error::Invalid.redact())?;
    let global = Config::read(&files.global_config)?;
    let mut budget = global.shutdown_budget()?;
    let mut binds = BTreeSet::new();
    bind(&mut binds, &global.listen)?;
    let mut names = BTreeSet::new();
    let mut communities = Vec::new();
    for path in files.community_configs {
        let community = CommunityConfig::read(&path)?;
        if community.domain != global.domain || !names.insert(community.community.clone()) {
            return Err(Error::Invalid);
        }
        bind(&mut binds, &community.listen)?;
        budget = budget.min(community.shutdown_budget()?);
        communities.push(community);
    }
    let root = match files.root_board {
        None => None,
        Some(files) => {
            if files.purpose_key_file.is_empty() {
                return Err(Error::Invalid);
            }
            let root = RootCommunityConfig::read(&files.root_board_config)?;
            if root.domain() != global.domain {
                return Err(Error::Invalid);
            }
            bind(&mut binds, root.listen())?;
            budget = budget.min(root.shutdown_budget()?);
            // The root board owns the reserved scopes; no community may take them.
            let mut hosts = BTreeSet::new();
            hosts.insert(host(root.community_name(), root.domain())?);
            hosts.insert(host(
                &format!("admin.{}", root.community_name()),
                root.domain(),
            )?);
            for community in &communities {
                for scope in [
                    community.community.clone(),
                    format!("admin.{}", community.community),
                ] {
                    if !hosts.insert(host(&scope, &community.domain)?) {
                        return Err(Error::Invalid);
                    }
                }
            }
            let key = cpsd::IssuerKey::from_secret_bytes(&Config::secret(&files.purpose_key_file)?)
                .map_err(Error::Invalid.redact())?;
            Some((root, key))
        }
    };
    let hub = match &files.hub {
        Some(hub) => Some(hub::read(hub)?),
        None => None,
    };
    Ok(Prepared {
        global,
        communities,
        root,
        hub,
        budget,
    })
}

fn bind(used: &mut BTreeSet<SocketAddr>, input: &str) -> Result<()> {
    let address: SocketAddr = input.parse().map_err(Error::Invalid.redact())?;
    if used.iter().any(|other| {
        other.port() == address.port()
            && (other.ip().to_canonical() == address.ip().to_canonical()
                || other.ip().is_unspecified()
                || address.ip().is_unspecified())
    }) {
        return Err(Error::Invalid);
    }
    used.insert(address);
    Ok(())
}

#[cfg(test)]
#[path = "platform/tests.rs"]
mod tests;
