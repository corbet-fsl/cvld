//! One trusted process owns the ROOT purpose key and explicitly linked sources.
use crate::{
    config::{CommunityConfig, RootCommunityConfig},
    error::{Error, Result},
    service::{Door, NativeConstruction, SystemClock},
    signals,
};
use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};

pub(super) mod config;
pub(super) mod lifecycle;

pub(super) struct Service {
    pub(super) address: String,
    pub(super) door: Door,
    /// Replaces the door's own router (the multi-tenant front).
    pub(super) router: Option<axum::Router>,
    /// Hosting hub whose dynamic doors this service fences, joins and maintains.
    pub(super) hub: Option<Arc<crate::hub::Hub>>,
}
impl Service {
    pub(super) fn new(address: String, door: Door) -> Self {
        Self {
            address,
            door,
            router: None,
            hub: None,
        }
    }
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
    clock: Arc<dyn crate::service::Clock>,
    construction: &NativeConstruction,
    services: &mut Vec<Service>,
    listeners: &mut Vec<tokio::net::TcpListener>,
) -> Result<()> {
    let address = root.listen().to_owned();
    let door =
        Door::root_board_with_construction(root, clock.clone(), construction.clone()).await?;
    // Retain each completed Door before the next await. Abandoned later
    // startup still fences and joins every earlier native owner.
    services.push(Service::new(address, door));
    let purpose = services[0].door.root_board_purpose(key).await?;
    for source in sources {
        let address = source.listen.clone();
        let door =
            Door::community_with_construction(source, clock.clone(), construction.clone()).await?;
        services.push(Service::new(address, door));
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
mod tests;
