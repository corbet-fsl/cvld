//! Original payment planning and dispatch boundaries; HTTP is entirely inert.
#![cfg(feature = "server")]
use crate::payment_support;
use crpt::facilitator::{DispatchGuard, Exchange, Transport};
use cvld::payments::{self, *};
use payment_support::*;
use serde_json::json;
use std::sync::{Arc, atomic::Ordering};
use x402_types::proto::{
    SettleRequest, SettleResponse, SupportedResponse, VerifyRequest, VerifyResponse,
};

fn context(owner: &Owner, expires: u64) -> PreparationContext {
    PreparationContext {
        owner: owner.clone(),
        session_expires: expires,
        observed: NOW,
        policy: PolicyBinding {
            epoch: 1,
            revision: 1,
        },
    }
}

struct RollbackAfterDiscovery {
    wire: Arc<Wire>,
    clock: Time,
}
impl Transport for RollbackAfterDiscovery {
    async fn supported_details(&self, guard: &DispatchGuard<'_>) -> Exchange<SupportedResponse> {
        let response = Inert(self.wire.clone()).supported_details(guard).await;
        self.clock.set(NOW - 1);
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

#[tokio::test]
async fn actual_discovery_then_clock_rollback_retains_exposure_and_poisons_further_paid_work() {
    let directory = tempfile::tempdir().unwrap();
    let database = db(&directory.path().join("payments.db")).await;
    let clock = Time::new();
    let wire = Wire::new(Reply::Success);
    let mut host = PaymentHost::open(
        &database,
        config(directory.path()),
        "alpha".into(),
        "admission".into(),
        Arc::new(clock.clone()),
        Some(payments::transport::AnyTransport(Arc::new(
            RollbackAfterDiscovery {
                wire: wire.clone(),
                clock: clock.clone(),
            },
        ))),
    )
    .await
    .unwrap();
    let owner = owner("member");
    let preview = prepare(&mut host, &owner);
    let result = host
        .execute(
            &preview.operation,
            &preview.authorization,
            &owner,
            authority(clock.clone()),
        )
        .await;
    assert!(matches!(result, Err(Error::Uncertain)));
    let status = host.status(&preview.operation, &owner).await.unwrap();
    assert_eq!(status.outcome, PaymentOutcome::Uncertain);
    assert!(status.access.is_none());
    assert_eq!(wire.supported.load(Ordering::SeqCst), 1);
    assert_eq!(wire.verified.load(Ordering::SeqCst), 0);
    assert_eq!(wire.settled.load(Ordering::SeqCst), 0);
    assert_eq!(
        database
            .community("alpha")
            .unwrap()
            .query(
                "SELECT exposure FROM cvld_payment_budget WHERE id = ?1",
                ["fees"]
            )
            .await
            .unwrap()[0]
            .get_i64(0)
            .unwrap(),
        4
    );
    clock.set(NOW);
    assert!(matches!(host.offer(), Err(Error::Expired)));
    assert!(matches!(
        host.prepare(context(&owner, 190), "paid-access", payload(), amount(12)),
        Err(Error::Expired)
    ));
    assert!(matches!(
        host.execute(
            &preview.operation,
            &preview.authorization,
            &owner,
            authority(clock)
        )
        .await,
        Err(Error::Conflict)
    ));
    assert!(host.access(&preview.operation, &owner).is_err());
}

#[tokio::test]
async fn invalid_member_inputs_never_reserve_fees_or_reach_the_facilitator() {
    let directory = tempfile::tempdir().unwrap();
    let database = db(&directory.path().join("payments.db")).await;
    let clock = Time::new();
    let wire = Wire::new(Reply::Success);
    let mut host = open_host(&database, config(directory.path()), clock, wire.clone()).await;
    let owner = owner("member");
    for payload in [
        vec![],
        b"{invalid".to_vec(),
        b"[]".to_vec(),
        vec![b' '; 65536],
    ] {
        assert!(matches!(
            host.prepare(context(&owner, 190), "paid-access", payload, amount(12)),
            Err(Error::Input)
        ));
    }
    assert!(matches!(
        host.prepare(context(&owner, 190), "other-option", payload(), amount(12)),
        Err(Error::Refused)
    ));
    let mut absent_subject = owner.clone();
    absent_subject.subject.clear();
    assert!(matches!(
        host.prepare(
            context(&absent_subject, 190),
            "paid-access",
            payload(),
            amount(12)
        ),
        Err(Error::Refused)
    ));
    for mut budget in [amount(3), amount(12)] {
        if budget.atoms == 12 {
            budget.unit = "different-denomination".into();
        }
        assert!(matches!(
            host.prepare(context(&owner, 190), "paid-access", payload(), budget),
            Err(Error::Budget)
        ));
    }
    assert!(matches!(
        host.prepare(context(&owner, NOW), "paid-access", payload(), amount(12)),
        Err(Error::Expired)
    ));
    assert!(
        database
            .community("alpha")
            .unwrap()
            .query("SELECT id FROM cvld_payment_operation", ())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(wire.supported.load(Ordering::SeqCst), 0);
    assert_eq!(wire.verified.load(Ordering::SeqCst), 0);
    assert_eq!(wire.settled.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn capacity_pruning_never_renews_the_original_operation_or_changes_its_owner() {
    let directory = tempfile::tempdir().unwrap();
    let database = db(&directory.path().join("payments.db")).await;
    let clock = Time::new();
    let wire = Wire::new(Reply::Success);
    let mut configuration = config(directory.path());
    configuration.capacity = 1;
    let mut host = open_host(&database, configuration, clock.clone(), wire.clone()).await;
    let owner = owner("member");
    let first = host
        .prepare(
            context(&owner, NOW + 2),
            "paid-access",
            payload(),
            amount(12),
        )
        .unwrap();
    assert_eq!(first.expires_at, NOW + 2);
    assert_eq!(
        host.status(&first.operation, &owner).await.unwrap().outcome,
        PaymentOutcome::Prepared
    );
    assert!(matches!(
        host.prepare(context(&owner, 190), "paid-access", payload(), amount(12)),
        Err(Error::Capacity)
    ));
    for field in ["subject", "user", "session", "credential"] {
        let mut foreign = owner.clone();
        match field {
            "subject" => foreign.subject = "other".into(),
            "user" => foreign.user = ckyh::Uuid::from_bytes([9; 16]),
            "session" => foreign.session = [9; 32],
            _ => foreign.credential = vec![9].into(),
        }
        assert!(matches!(
            host.execution_context(&first.operation, &foreign),
            Err(Error::Refused)
        ));
        assert!(matches!(
            host.status(&first.operation, &foreign).await,
            Err(Error::Refused)
        ));
    }
    assert!(matches!(
        host.check_release(&first.operation, &owner, NOW + 1),
        Err(Error::Expired)
    ));
    clock.set(first.expires_at);
    let second = host
        .prepare(context(&owner, 190), "paid-access", payload(), amount(12))
        .unwrap();
    assert_ne!(first.operation, second.operation);
    assert!(host.execution_context(&first.operation, &owner).is_err());
    assert!(host.status(&first.operation, &owner).await.is_err());
    for operation in [
        "short".to_owned(),
        "g".repeat(64),
        format!("{}{}", "0".repeat(32), "g".repeat(32)),
    ] {
        assert!(matches!(
            host.status(&operation, &owner).await,
            Err(Error::Input)
        ));
    }
    assert_eq!(wire.supported.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn altered_payment_principal_recipient_network_or_resource_never_reaches_http() {
    for field in ["amount", "asset", "network", "payTo", "resource"] {
        let directory = tempfile::tempdir().unwrap();
        let database = db(&directory.path().join("payments.db")).await;
        let clock = Time::new();
        let wire = Wire::new(Reply::Success);
        let mut host = open_host(
            &database,
            config(directory.path()),
            clock.clone(),
            wire.clone(),
        )
        .await;
        let owner = owner("member");
        let mut evidence: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        if field == "resource" {
            evidence["resource"]["url"] = json!("https://other-merchant.example.test/access");
        } else {
            evidence["accepted"][field] = json!(if field == "network" {
                "eip155:1"
            } else {
                "changed"
            });
        }
        let preview = host
            .prepare(
                context(&owner, 190),
                "paid-access",
                serde_json::to_vec(&evidence).unwrap(),
                amount(12),
            )
            .unwrap();
        let result = host
            .execute(
                &preview.operation,
                &preview.authorization,
                &owner,
                authority(clock.clone()),
            )
            .await
            .unwrap();
        assert_eq!(result.outcome, PaymentOutcome::Uncertain);
        assert!(result.access.is_none());
        assert!(host.access(&preview.operation, &owner).is_err());
        assert!(matches!(
            host.execute(
                &preview.operation,
                &preview.authorization,
                &owner,
                authority(clock)
            )
            .await,
            Err(Error::Conflict)
        ));
        assert_eq!(wire.supported.load(Ordering::SeqCst), 0, "{field}");
        assert_eq!(wire.verified.load(Ordering::SeqCst), 0, "{field}");
        assert_eq!(wire.settled.load(Ordering::SeqCst), 0, "{field}");
        assert_eq!(
            database
                .community("alpha")
                .unwrap()
                .query(
                    "SELECT exposure FROM cvld_payment_budget WHERE id = ?1",
                    ["fees"]
                )
                .await
                .unwrap()[0]
                .get_i64(0)
                .unwrap(),
            4
        );
    }
}

fn simulation() -> serde_json::Value {
    json!({"dummy_offer":offer(),"dummy_payload":payload(),"access":{"level":"explicit-dummy-level","starts_at":NOW,"expires_at":NOW+86400},"maximum":amount(4),"actual_fee":null,"budget":amount(12),"source":"explicit hypothetical tariff","expires_at":NOW+60,"outcome":"settled","satisfies_terms":true})
}
fn simulate(
    value: serde_json::Value,
) -> payments::Result<payments::simulation::SimulationResponse> {
    payments::simulation::simulate(serde_json::from_value(value).unwrap(), NOW)
}

#[test]
fn local_payment_outcomes_and_unexpected_fees_never_fabricate_paid_access() {
    let success = simulate(simulation()).unwrap();
    assert!(success.simulated);
    assert_eq!(success.outcome, PaymentOutcome::Settled);
    assert_eq!(success.access.unwrap().level, "explicit-dummy-level");
    assert_eq!(success.exposure.atoms, 4);
    assert!(!success.charge_violation);
    for (state, expected) in [
        ("refused", PaymentOutcome::Refused),
        ("pending", PaymentOutcome::Pending),
        ("uncertain", PaymentOutcome::Uncertain),
    ] {
        let mut value = simulation();
        value["outcome"] = json!(state);
        let result = simulate(value).unwrap();
        assert_eq!(result.outcome, expected);
        assert!(result.access.is_none());
        assert_eq!(result.exposure.atoms, 4);
    }
    let mut unsatisfied = simulation();
    unsatisfied["satisfies_terms"] = json!(false);
    assert!(matches!(simulate(unsatisfied), Err(Error::Refused)));
    for fee in [
        amount(5),
        Amount {
            unit: "foreign-fee".into(),
            scale: 0,
            atoms: 2,
        },
    ] {
        let mut value = simulation();
        value["actual_fee"] = serde_json::to_value(fee).unwrap();
        let result = simulate(value).unwrap();
        assert!(result.charge_violation);
        assert!(result.access.is_none());
    }
    let mut unknown = simulation();
    unknown["maximum"] = serde_json::Value::Null;
    assert!(matches!(simulate(unknown), Err(Error::Budget)));
    let mut expired = simulation();
    expired["expires_at"] = json!(NOW);
    assert!(matches!(simulate(expired), Err(Error::Budget)));
}
