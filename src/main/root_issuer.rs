//! One trusted process owns the ROOT purpose key and explicitly linked sources.
use super::*;
use cvld::service::NativeConstruction;

#[path = "root_issuer/config.rs"]
mod config;
#[path = "root_issuer/lifecycle.rs"]
mod lifecycle;

struct Service {
    address: String,
    door: Door,
}

pub(super) async fn run(path: &str, deadline: Arc<OnceLock<Instant>>) -> Result<()> {
    // Parse every explicit component, identity, bind and key before creating
    // native owners. Ordinary source configurations never receive this key.
    let config::Prepared {
        root,
        sources,
        key,
        budget,
    } = config::read(path)?;
    let signals = signals::Signals::install(budget, deadline.clone()).await?;
    let construction = NativeConstruction::new();
    let mut services = Vec::new();
    let mut listeners = Vec::new();
    let mut interrupted = signals.receiver();
    let opening = open_components(
        root,
        sources,
        key,
        Arc::new(SystemClock),
        &construction,
        &mut services,
        &mut listeners,
    );
    let opened = signals::open(opening, &mut interrupted).await;
    match opened {
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
    root: RootCommunityConfig,
    sources: Vec<CommunityConfig>,
    key: cpsd::IssuerKey,
    clock: Arc<dyn cvld::service::Clock>,
    construction: &NativeConstruction,
    services: &mut Vec<Service>,
    listeners: &mut Vec<tokio::net::TcpListener>,
) -> Result<()> {
    let address = root.listen().to_owned();
    let door =
        Door::root_board_with_construction(root, clock.clone(), construction.clone()).await?;
    // Retain each completed Door before the next await. Abandoned later
    // startup still fences and joins every earlier native owner.
    services.push(Service { address, door });
    let purpose = services[0].door.root_board_purpose(key).await?;
    for source in sources {
        let address = source.listen.clone();
        let door =
            Door::community_with_construction(source, clock.clone(), construction.clone()).await?;
        services.push(Service { address, door });
        services
            .last()
            .ok_or(Error::Unavailable)?
            .door
            .attach_root_board_purpose(purpose.clone())
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

#[cfg(all(test, feature = "development-gate"))]
#[path = "root_issuer/tests.rs"]
mod tests;
