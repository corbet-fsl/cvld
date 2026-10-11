use super::*;
use tokio::{sync::watch, task::JoinSet};

fn fence(services: &[Service], construction: &NativeConstruction) -> bool {
    let mut failed = construction.begin_shutdown().is_err();
    // Evaluate every initiation, even if another owner refuses. Never wait for
    // one native thread while a different Door can still accept native work.
    for service in services {
        failed |= service.door.begin_shutdown_accounts().is_err();
    }
    failed
}

pub(super) async fn close(services: &[Service], construction: &NativeConstruction) -> Result<()> {
    let mut failed = fence(services, construction);
    for service in services {
        failed |= service.door.shutdown_accounts().await.is_err();
    }
    failed |= construction.shutdown().await.is_err();
    if failed {
        Err(Error::Unavailable)
    } else {
        Ok(())
    }
}

pub(super) async fn serve(
    services: &[Service],
    listeners: Vec<tokio::net::TcpListener>,
    construction: &NativeConstruction,
    signals: &signals::Signals,
    budget: Duration,
    deadline: Arc<OnceLock<Instant>>,
) -> Result<()> {
    let (stop, _) = watch::channel(false);
    let mut servers = JoinSet::new();
    let mut maintenance = JoinSet::new();
    for (service, listener) in services.iter().zip(listeners) {
        let door = service.door.clone();
        let mut stopping = stop.subscribe();
        servers.spawn(async move {
            axum::serve(listener, api::router(door))
                .with_graceful_shutdown(async move {
                    if !*stopping.borrow_and_update() {
                        let _ = stopping.changed().await;
                    }
                })
                .await
                .map_err(Error::Unavailable.redact())
        });
        let door = service.door.clone();
        maintenance.spawn(async move {
            // Same existing Door upkeep cadence; each original owner enforces
            // its own authenticated publication and accounting deadlines.
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let _ = door.maintain().await;
            }
        });
    }
    let mut signal = signals.receiver();
    let (until, unexpected) = tokio::select! {
        result = signals::wait(&mut signal) => {
            match result { Ok(until) => (until, false), Err(_) => (Instant::now(), true) }
        }
        _ = servers.join_next() => {
            let now = Instant::now();
            let until = now.checked_add(budget).unwrap_or(now);
            let _ = deadline.set(until);
            (*deadline.get().unwrap_or(&until), true)
        }
    };
    stop.send_replace(true);
    maintenance.abort_all();
    let began_failed = fence(services, construction);
    let drain = async {
        let mut failed = false;
        while let Some(result) = servers.join_next().await {
            failed |= !matches!(result, Ok(Ok(())));
        }
        failed
    };
    let (drained, joined) = tokio::join!(
        tokio::time::timeout_at(tokio::time::Instant::from_std(until), drain),
        close(services, construction),
    );
    if drained.is_err() {
        servers.abort_all();
    }
    while servers.join_next().await.is_some() {}
    while maintenance.join_next().await.is_some() {}
    joined?;
    if unexpected || began_failed || drained.unwrap_or(true) {
        Err(Error::Unavailable)
    } else {
        Ok(())
    }
}
