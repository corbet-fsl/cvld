//! An explicit caller policy joins real contact passports to paid membership.
use super::*;

#[allow(dead_code)]
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

/// The paid-access admission policy this caller applies after founding.
#[allow(dead_code)]
fn paid_policy() -> cplc::crbk::ActionPolicy {
    use cplc::crbk;
    crbk::ActionPolicy {
        all_of: [
            (crbk::GateLevel::Global, "cphn", cmty::PASSPORT_PROVIDER),
            (crbk::GateLevel::Global, "cmbx", cmty::PASSPORT_PROVIDER),
            (crbk::GateLevel::Community, "crpt", "fixture-facilitator"),
        ]
        .into_iter()
        .map(|(level, gate, provider)| crbk::Requirement {
            gate: gate.into(),
            level,
            provider: Some(provider.into()),
        })
        .collect(),
        ..Default::default()
    }
}

/// Found the community exactly as a real founder does: a registered recipient with
/// a Global passport, the creation claim and ordinary full-gate redemption.
#[allow(dead_code)]
async fn found(running: &Running, global: &Running, cohort: u64) -> Member {
    use cvld::service::Clock as _;
    // The founder is a second person with their own verified phone and mailbox.
    let secret = cpsd::HolderSecret::generate(&mut cpsd::rand::rngs::OsRng);
    let (_, passport, _) = super::contacts::wallet_with_contacts(
        global,
        cohort,
        &secret,
        ["+12025550177", "Founder+alias@EXAMPLE.test"],
    )
    .await;
    let host = HOST;
    let founder = enrol_community(running, host, &passport).await;
    let secret = b"fixture-creation-claim-secret!!".to_vec();
    running
        .door
        .arm_creation(&secret, running.clock.now() + 300)
        .await
        .unwrap();
    let api = client(running, host, Some(&founder.session));
    let claimed = api
        .call("community_creation_claim", json!({ "claim": secret }))
        .await
        .unwrap();
    let invitation = claimed["id"].as_str().unwrap().to_owned();
    api.call("handle_reserve", json!({"handle":"founding_root"}))
        .await
        .unwrap();
    let proof = presentation(running, host, Some(&founder.session), &passport).await;
    let issued: CredentialResponse = serde_json::from_value(
        api.call(
            "credential_issue",
            json!({"presentation":proof,"devices":[founder.signing_key],"creation":invitation}),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(issued.lobby.state, "admitted");
    founder
}

#[allow(dead_code)]
pub(super) async fn community_founded(
    global: &Running,
    cohort: u64,
    public: &GlobalPublic,
    wire: Arc<payment_support::Wire>,
) -> Running {
    use cplc::crbk;
    use cvld::service::Clock as _;
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(std::sync::atomic::AtomicU64::new(NOW)));
    // The founding rulebook defines the contact and paid-access gates but, like any
    // new community, starts from the default admission policy.
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
    // Founding admission: a passport with verified phone and mailbox.
    let founding_policy = crbk::ActionPolicy {
        all_of: [
            (crbk::GateLevel::Global, "cphn", cmty::PASSPORT_PROVIDER),
            (crbk::GateLevel::Global, "cmbx", cmty::PASSPORT_PROVIDER),
        ]
        .into_iter()
        .map(|(level, gate, provider)| crbk::Requirement {
            gate: gate.into(),
            level,
            provider: Some(provider.into()),
        })
        .collect(),
        ..Default::default()
    };
    rules
        .set_community(
            &crbk::action_key(cmty::ADMISSION_ACTION),
            Some(serde_json::to_value(founding_policy).unwrap()),
        )
        .unwrap();
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
        let founder = found(&founding, global, cohort).await;
        founding.task.abort();
        founder
    };
    // The same community (same database) now serves under its paid-access configuration.
    let mut config = community_config(dir.path(), "alpha", public, 200);
    config.global_gates = vec!["cphn".into(), "cmbx".into()];
    let mut paid = payment_support::config(dir.path());
    paid.tariff.valid_until = NOW + 500;
    paid.access.starts_at = NOW;
    paid.access.expires_at = (NOW / 86400 + 20) * 86400;
    config.payments = Some(paid);
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
    let running = Running {
        base,
        door,
        clock,
        task,
        dir,
    };
    // The community's admin applies the caller's paid-access policy through the real
    // setting action; it applies from its effective time, so the clock moves there first.
    let admin_host = "api.admin.alpha.example.test";
    let session = login(
        &running,
        admin_host,
        &mut founder.authenticator,
        &founder.user,
        &founder.credential,
    )
    .await;
    let effective = running.clock.now() + 1;
    client(&running, admin_host, Some(&session))
        .call(
            "setting_set",
            json!({
                "key": crbk::action_key(cmty::ADMISSION_ACTION),
                "value": serde_json::to_value(paid_policy()).unwrap(),
                "inherit": false,
                "effective_at": effective,
            }),
        )
        .await
        .unwrap();
    running.clock.set(effective);
    // The service's maintenance tick (as the daemon runs it) publishes the revision now in force.
    running.door.maintain().await.unwrap();
    running
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
