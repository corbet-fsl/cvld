//! Actual member/session/policy and paid gate composition; no vendor network.
#![cfg(feature = "development-gate")]
use crate::payment_support;
use crate::support;
use crpt::facilitator::{DispatchGuard, Exchange, Transport};
use cvld::{api::*, payments, service::Door};
use payment_support::{Inert, Reply, Wire};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use support::*;
use x402_types::proto::{
    SettleRequest, SettleResponse, SupportedResponse, VerifyRequest, VerifyResponse,
};
const HOST: &str = "api.alpha.example.test";
type Revocation = (
    ckyh::Passkeys<ckyh::LibsqlStore>,
    ckyh::Uuid,
    ckyh::CredentialID,
);
struct RevokingWire {
    wire: Arc<Wire>,
    original: std::sync::Mutex<Option<Revocation>>,
}
impl Transport for RevokingWire {
    async fn supported_details(&self, guard: &DispatchGuard<'_>) -> Exchange<SupportedResponse> {
        let response = Inert(self.wire.clone()).supported_details(guard).await;
        let revoke = self.original.lock().unwrap().take();
        if let Some((keyhole, user, credential)) = revoke {
            tokio::task::spawn_blocking(move || keyhole.revoke(user, &credential))
                .await
                .unwrap()
                .unwrap();
        }
        response
    }
    async fn verify_details(
        &self,
        request: &VerifyRequest,
        guard: &DispatchGuard<'_>,
    ) -> Exchange<VerifyResponse> {
        Inert(self.wire.clone())
            .verify_details(request, guard)
            .await
    }
    async fn settle_details(
        &self,
        request: &SettleRequest,
        guard: &DispatchGuard<'_>,
    ) -> Exchange<SettleResponse> {
        Inert(self.wire.clone())
            .settle_details(request, guard)
            .await
    }
}

async fn configured(
    public: &GlobalPublic,
    wire: payments::transport::AnyTransport,
    enabled: bool,
) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let mut config = community_config(dir.path(), "alpha", public, 200);
    // Explicit test caller policy: real global passport plus this one actual
    // community paid-access gate. The payment library supplies no such policy.
    let encoded = serde_json::to_string(&community_rules())
        .unwrap()
        .replace("cvch", "crpt")
        .replace("sponsor", "fixture-facilitator");
    let mut rules: cmty::cplc::crbk::Rulebook = serde_json::from_str(&encoded).unwrap();
    if !enabled {
        rules
            .set_community(
                &cmty::cplc::crbk::provider_key(
                    cmty::cplc::crbk::GateLevel::Community,
                    "crpt",
                    "fixture-facilitator",
                ),
                Some(json!(false)),
            )
            .unwrap();
    }
    std::fs::write(&config.rulebook_file, serde_json::to_vec(&rules).unwrap()).unwrap();
    let mut paid = payment_support::config(dir.path());
    paid.tariff.valid_until = NOW + 500;
    paid.access.starts_at = NOW;
    paid.access.expires_at = (NOW / 86400 + 20) * 86400;
    config.payments = Some(paid);
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let door = Door::community_with_payment_transport(config, clock.clone(), wire)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Running {
        base,
        door,
        clock,
        task,
        dir,
    }
}
/// `configured`, but the community is founded the way a real one is, and only then does it ask for the
/// paid-access gate. The first admission of a community is its creator's (cmbr refuses any other member
/// while no first admin exists), so a member issued a credential here needs a founded community: found it
/// under the default admission policy, serve it again under the payment configuration, and let the
/// founder apply the caller's policy (development passport plus the paid-access gate) through the real
/// setting action, as the production journey does.
async fn configured_founded(
    public: &GlobalPublic,
    wire: payments::transport::AnyTransport,
) -> Running {
    use cmty::cplc::crbk;
    use cvld::service::Clock as _;
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let mut rules = community_rules();
    for key in [
        crbk::gate_key(crbk::GateLevel::Community, "crpt"),
        crbk::provider_key(crbk::GateLevel::Community, "crpt", "fixture-facilitator"),
    ] {
        rules
            .define(
                key,
                crbk::Setting {
                    value_type: crbk::SettingType::Boolean,
                    nullable: false,
                    default: json!(true),
                    bounds: crbk::Bounds::default(),
                    lowest_layer: crbk::Layer::Community,
                    kind: crbk::SettingKind::Technical,
                },
            )
            .unwrap();
    }
    let config = community_config(dir.path(), "alpha", public, 200);
    std::fs::write(&config.rulebook_file, serde_json::to_vec(&rules).unwrap()).unwrap();
    let mut founder = {
        let door = Door::community(config, clock.clone()).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let router = cvld::api::router(door.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let founding = Running {
            base,
            door,
            clock: clock.clone(),
            task,
            dir: tempfile::tempdir().unwrap(),
        };
        active::found(&founding, "alpha", public).await;
        let founder = active::take_founder(&founding).unwrap();
        founding.task.abort();
        founder
    };
    // The same community (same database) now serves under its payment configuration.
    let mut config = community_config(dir.path(), "alpha", public, 200);
    let mut paid = payment_support::config(dir.path());
    paid.tariff.valid_until = NOW + 500;
    paid.access.starts_at = NOW;
    paid.access.expires_at = (NOW / 86400 + 20) * 86400;
    config.payments = Some(paid);
    let door = Door::community_with_payment_transport(config, clock.clone(), wire)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let running = Running {
        base,
        door,
        clock,
        task,
        dir,
    };
    // The policy applies from its effective time, so the clock moves there first.
    let admin_host = "api.admin.alpha.example.test";
    let session = login(
        &running,
        admin_host,
        &mut founder.authenticator,
        &founder.user,
        &founder.credential,
    )
    .await;
    let policy = crbk::ActionPolicy {
        all_of: vec![
            crbk::Requirement {
                gate: "development".into(),
                level: crbk::GateLevel::Global,
                provider: None,
            },
            crbk::Requirement {
                gate: "crpt".into(),
                level: crbk::GateLevel::Community,
                provider: Some("fixture-facilitator".into()),
            },
        ],
        ..Default::default()
    };
    let effective = running.clock.now() + 1;
    client(&running, admin_host, Some(&session))
        .call(
            "setting_set",
            json!({
                "key": crbk::action_key(cmty::ADMISSION_ACTION),
                "value": serde_json::to_value(policy).unwrap(),
                "inherit": false,
                "effective_at": effective,
            }),
        )
        .await
        .unwrap();
    running.clock.set(effective);
    // The service's maintenance tick publishes the revision now in force.
    running.door.maintain().await.unwrap();
    running
}
fn plan() -> Value {
    json!({"option":"paid-access","payload":payment_support::payload(),"budget":payment_support::amount(12)})
}
async fn execute(service: &Running, member: &Member, preview: &Value) -> Value {
    client(service, HOST, Some(&member.session))
        .call(
            "payment_execute",
            json!({"operation":preview["operation"],"authorization":preview["authorization"]}),
        )
        .await
        .unwrap()
}

#[path = "payment_routes/refusals.rs"]
mod refusals;
#[path = "payment_routes/revocation.rs"]
mod revocation;
#[path = "payment_routes/round_trip.rs"]
mod round_trip;
#[path = "payment_routes/simulation.rs"]
mod simulation;
