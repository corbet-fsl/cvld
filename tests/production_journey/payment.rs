//! An explicit caller policy joins real contact passports to paid membership.
use super::*;

pub(super) async fn community(public: &GlobalPublic, wire: Arc<payment_support::Wire>) -> Running {
    use cplc::crbk;
    let dir = tempfile::tempdir().unwrap();
    let mut config = community_config(dir.path(), "alpha", public, 200);
    config.global_gates = vec!["cphn".into(), "cmbx".into()];
    let mut rules = community_rules();
    for (level, gate, provider) in [
        (crbk::GateLevel::Global, "cphn", cmty::PASSPORT_PROVIDER),
        (crbk::GateLevel::Global, "cmbx", cmty::PASSPORT_PROVIDER),
        (crbk::GateLevel::Community, "crpt", "fixture-facilitator"),
    ] {
        for key in [
            crbk::gate_key(level, gate),
            crbk::provider_key(level, gate, provider),
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
    }
    let policy = crbk::ActionPolicy {
        all_of: [
            (crbk::GateLevel::Global, "cphn", cmty::PASSPORT_PROVIDER),
            (crbk::GateLevel::Global, "cmbx", cmty::PASSPORT_PROVIDER),
            (crbk::GateLevel::Community, "crpt", "fixture-facilitator"),
        ]
        .into_iter()
        .map(|(level, gate, provider)| crbk::Requirement {
            level,
            gate: gate.into(),
            provider: Some(provider.into()),
        })
        .collect(),
        ..Default::default()
    };
    rules
        .set_community(
            &crbk::action_key(cmty::ADMISSION_ACTION),
            Some(serde_json::to_value(policy).unwrap()),
        )
        .unwrap();
    std::fs::write(&config.rulebook_file, serde_json::to_vec(&rules).unwrap()).unwrap();
    let mut paid = payment_support::config(dir.path());
    paid.tariff.valid_until = NOW + 500;
    paid.access.starts_at = NOW;
    paid.access.expires_at = (NOW / 86400 + 20) * 86400;
    config.payments = Some(paid);
    let clock = Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)));
    let door = Door::community_with_payment_transport(
        config,
        clock.clone(),
        cvld::payments::transport::AnyTransport(Arc::new(payment_support::Inert(wire))),
    )
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

pub(super) async fn settle(service: &Running, member: &Member) {
    let api = client(service, HOST, Some(&member.session));
    let preview = api
        .call(
            "payment_plan",
            json!({
                "option":"paid-access", "payload":payment_support::payload(),
                "budget":payment_support::amount(12),
            }),
        )
        .await
        .unwrap();
    let receipt = api
        .call(
            "payment_execute",
            json!({
                "operation":preview["operation"], "authorization":preview["authorization"],
            }),
        )
        .await
        .unwrap();
    assert_eq!(receipt["outcome"], "settled");
    assert_eq!(receipt["access"]["level"], "caller-level");
    let accepted = api
        .call("payment_accept", json!({"operation":preview["operation"]}))
        .await
        .unwrap();
    assert_eq!(accepted["access"]["level"], "caller-level");
    for body in [preview, receipt, accepted] {
        let encoded = serde_json::to_string(&body).unwrap();
        for raw in [
            "PRIVATE-PAYER",
            "PRIVATE-SIGNATURE",
            "PRIVATE-CHAIN-TRANSACTION",
            "fixture-asset",
        ] {
            assert!(!encoded.contains(raw));
        }
    }
}
