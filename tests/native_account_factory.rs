//! Actual application Store and factory; an activation probe admits no member.
//! Required inputs must be generated for alpha at NOW before proving. Missing
//! inputs fail explicitly; historical differently scoped fixtures are not used.
#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
#[path = "native_account_factory/cuts.rs"]
mod cuts;
#[path = "native_account_factory/fixture.rs"]
mod fixture;
mod support;

use cvld::{
    api::TrustFeed,
    service::{Clock, Door, NativeConstruction},
};
use fixture::Fixture;
use std::sync::Arc;
use support::NOW;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_factory_publishes_daily_capability_and_reopens_the_same_store() {
    let fixture = Fixture::new().await;
    let clock = Arc::new(cuts::ObservedClock::steady());
    let construction = NativeConstruction::new();
    let door = Door::community_with_construction(
        fixture.duplicate_config(),
        clock.clone(),
        construction.clone(),
    )
    .await
    .expect("actual configured native factory must complete");
    let calls = clock.calls();
    assert!(calls > 3);
    let feed = fixture.feed(&door).await;
    fixture.check_feed(&feed);
    let rows = fixture.native_rows().await;
    assert!(rows.iter().any(|(key, _)| key == b"settlement-mode:v1"));
    door.shutdown_accounts().await.unwrap();
    construction.shutdown().await.unwrap();
    drop(door);
    let reopened_owner = NativeConstruction::new();
    let reopened = Door::community_with_construction(
        fixture.duplicate_config(),
        Arc::new(cuts::ObservedClock::steady()),
        reopened_owner.clone(),
    )
    .await
    .expect("same native activation and provisioned issuer must reopen");
    fixture.check_feed(&fixture.feed(&reopened).await);
    assert_eq!(fixture.native_rows().await, rows);
    reopened.shutdown_accounts().await.unwrap();
    reopened_owner.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupted_actual_activation_proof_never_installs_daily_mode() {
    let fixture = Fixture::new().await;
    let account = fixture.config.accounting.as_ref().unwrap();
    let mut proof: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&account.activation_proof_file).unwrap()).unwrap();
    let encoded = proof["proofs"][0]["proof"].as_str().unwrap();
    assert!(encoded.len() > 2);
    let mut changed = encoded.to_owned();
    let last = u8::from_str_radix(&encoded[encoded.len() - 2..], 16).unwrap();
    changed.replace_range(encoded.len() - 2.., &format!("{:02x}", last ^ 1));
    proof["proofs"][0]["proof"] = changed.into();
    std::fs::write(
        &account.activation_proof_file,
        serde_json::to_vec(&proof).unwrap(),
    )
    .unwrap();
    let owner = NativeConstruction::new();
    let result = Door::community_with_construction(
        fixture.duplicate_config(),
        Arc::new(cuts::ObservedClock::steady()),
        owner.clone(),
    )
    .await;
    assert!(matches!(result, Err(cvld::error::Error::Invalid)));
    owner.shutdown().await.unwrap();
    assert!(
        !fixture
            .native_rows()
            .await
            .iter()
            .any(|(key, _)| key == b"settlement-mode:v1")
    );
}
