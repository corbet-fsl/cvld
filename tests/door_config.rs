#![cfg(feature = "development-gate")]
//! Services refuse every unusable configuration before they accept a request.
mod support;
use cvld::{
    api::GlobalPublic,
    config::{CommunityConfig, Config},
    error::Error,
    service::Door,
};
use serde_json::json;
use std::{
    path::Path,
    sync::{Arc, atomic::AtomicU64},
};
use support::*;

fn clock() -> Arc<TestClock> {
    Arc::new(TestClock(AtomicU64::new(NOW)))
}

async fn global_error(tune: impl FnOnce(&mut Config, &Path)) -> Option<Error> {
    let dir = tempfile::tempdir().unwrap();
    let mut config = global_config(dir.path(), 100, NOW).await;
    tune(&mut config, dir.path());
    Door::global(config, clock()).await.err()
}

async fn community_error(
    public: &GlobalPublic,
    tune: impl FnOnce(&mut CommunityConfig, &Path),
) -> Option<Error> {
    let dir = tempfile::tempdir().unwrap();
    let mut config = community_config(dir.path(), "errors", public, 100);
    tune(&mut config, dir.path());
    Door::community(config, clock()).await.err()
}

async fn public_of(service: &Running) -> GlobalPublic {
    serde_json::from_value(
        client(service, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap()
}

macro_rules! expect {
    ($outcome:expr, $pattern:pat) => {
        assert!(
            matches!($outcome.await, $pattern),
            "{}",
            stringify!($outcome)
        )
    };
}

#[tokio::test(flavor = "multi_thread")]
async fn global_limits_domains_and_identities_are_validated() {
    expect!(
        global_error(|c, _| c.domain = String::new()),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.domain = "UPPER.example.test".into()),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.domain = "bad_name.example.test".into()),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.publication_seconds = 86_400),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.publication_seconds = 200_000),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.root_user = "not-a-uuid".into()),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.session_seconds = 0),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.session_seconds = 3_601),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.throttle_burst = 0),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.throttle_interval_ms = 0),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| {
            c.throttle_burst = u32::MAX;
            c.throttle_interval_ms = 10_000_000_000;
        }),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.pending_capacity = usize::MAX),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, _| c.pending_capacity = 0),
        Some(Error::Unavailable)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn global_secrets_must_be_present_well_formed_and_the_right_size() {
    expect!(
        global_error(|c, dir| c.database_token_file = Some(write(dir, "token", &[0xff, 0xfe]))),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, dir| c.database_token_file = Some(write(dir, "token", b"remote-token"))),
        Some(Error::Unavailable)
    );
    expect!(
        global_error(|c, dir| {
            c.database_token_file = Some(dir.join("absent").to_str().unwrap().to_owned())
        }),
        Some(Error::Unavailable)
    );
    expect!(
        global_error(|c, _| c.database_url = "not a database url".into()),
        Some(Error::Unavailable)
    );
    expect!(
        global_error(|c, dir| c.root_bootstrap_file = Some(write(dir, "short", b"short"))),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, dir| c.root_bootstrap_file = Some(write(dir, "binary", &[0xff; 40]))),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, dir| {
            c.root_bootstrap_file = Some(dir.join("absent").to_str().unwrap().to_owned())
        }),
        Some(Error::Unavailable)
    );
    expect!(
        global_error(|c, dir| c.signing_seed_file = write(dir, "seed", b"too short")),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, dir| c.signing_seed_file = dir.join("absent").to_str().unwrap().into()),
        Some(Error::Unavailable)
    );
    expect!(
        global_error(|c, dir| c.uniqueness_key_file = write(dir, "unique", b"too short")),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, dir| c.issuer_key_file = write(dir, "issuer", b"not an issuer key")),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, dir| c.issuer_key_file = dir.join("absent").to_str().unwrap().into()),
        Some(Error::Unavailable)
    );
    expect!(
        global_error(|c, dir| c.policy_file = dir.join("absent").to_str().unwrap().into()),
        Some(Error::Unavailable)
    );
    expect!(
        global_error(|c, dir| {
            c.policy_authority_file = dir.join("absent").to_str().unwrap().into()
        }),
        Some(Error::Unavailable)
    );
    expect!(
        global_error(|c, dir| c.policy_authority_file = write(dir, "ring", b"not a key ring")),
        Some(Error::Invalid)
    );
    expect!(
        global_error(|c, dir| c.policy_file = write(dir, "policy", b"not a signed policy")),
        Some(Error::Refused)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn production_mode_refuses_the_development_policy() {
    // The production gate set never accepts the synthetic uniqueness gate.
    assert!(global_error(|c, _| c.development = false).await.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn hyphenated_numeric_domains_and_an_empty_database_token_are_accepted() {
    let side = tempfile::tempdir().unwrap();
    let token = write(side.path(), "token", b"");
    let service = global_tuned(100, move |c| {
        c.domain = "node-1.example.test".into();
        c.database_token_file = Some(token);
    })
    .await;
    let public = client(&service, "wallet.node-1.example.test", None)
        .call("global_public", json!({}))
        .await
        .unwrap();
    assert!(public["issuer"].is_array());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_host_without_a_provisioned_capability_cannot_enrol() {
    let service = global_tuned(100, |c| c.root_bootstrap_file = None).await;
    assert!(matches!(
        client(&service, ROOT, None)
            .call(
                "register_begin",
                json!({"bootstrap": "synthetic-operator-enrolment-capability", "passport": null})
            )
            .await,
        Err(Error::Forbidden)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_database_belongs_to_one_service_kind_and_scope() {
    let global = global(100).await;
    let public = public_of(&global).await;
    let dir = tempfile::tempdir().unwrap();
    let config = community_config(dir.path(), "first", &public, 100);
    let url = config.database_url.clone();
    let first = community_from(dir, config).await;
    // The global door cannot adopt a community's database, nor another scope.
    let adopt = {
        let url = url.clone();
        move |c: &mut Config, _: &Path| c.database_url = url
    };
    expect!(global_error(adopt), Some(Error::Unavailable));
    expect!(
        community_error(&public, move |c, _| {
            c.community = "second".into();
            c.database_url = url;
        }),
        Some(Error::Invalid)
    );
    drop(first);
}

#[tokio::test(flavor = "multi_thread")]
async fn community_limits_names_and_operators_are_validated() {
    let global = global(100).await;
    let public = public_of(&global).await;
    expect!(
        community_error(&public, |c, _| c.domain = String::new()),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, _| c.domain = "UPPER.example.test".into()),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, _| c.publication_seconds = 86_400),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, _| c.publication_seconds = 200_000),
        Some(Error::Invalid)
    );
    let long = "a".repeat(64);
    for name in [
        "",
        "Upper",
        "under_score",
        "root",
        "admin",
        "api",
        long.as_str(),
    ] {
        expect!(
            community_error(&public, |c, _| c.community = name.into()),
            Some(Error::Invalid)
        );
    }
    expect!(
        community_error(&public, |c, _| c.pending_capacity = 0),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, _| c.session_seconds = 0),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, _| c.session_seconds = 3_601),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, _| c.lease_months = 0),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, _| c.throttle_burst = 0),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, _| c.throttle_interval_ms = 0),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, _| c.admin.user = "not-a-uuid".into()),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, dir| c.root.bootstrap_file =
            Some(write(dir, "short", b"short"))),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, dir| c.admin.bootstrap_file =
            Some(dir.join("absent").to_str().unwrap().into())),
        Some(Error::Unavailable)
    );
    expect!(
        community_error(&public, |c, dir| c.admin.bootstrap_file =
            Some(write(dir, "binary", &[0xff; 40]))),
        Some(Error::Invalid)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn community_files_must_be_present_well_formed_and_distinct_from_the_global_key() {
    let global = global(100).await;
    let public = public_of(&global).await;
    expect!(
        community_error(&public, |c, dir| c.database_token_file =
            Some(write(dir, "token", &[0xff, 0xfe]))),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, dir| c.database_token_file =
            Some(write(dir, "token", b"remote-token"))),
        Some(Error::Unavailable)
    );
    expect!(
        community_error(&public, |c, dir| c.database_token_file =
            Some(dir.join("absent").to_str().unwrap().into())),
        Some(Error::Unavailable)
    );
    expect!(
        community_error(&public, |c, dir| c.global_key_ring_file =
            dir.join("absent").to_str().unwrap().into()),
        Some(Error::Unavailable)
    );
    expect!(
        community_error(&public, |c, dir| c.global_key_ring_file =
            write(dir, "ring", b"not a key ring")),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, dir| c.global_status_file =
            dir.join("absent").to_str().unwrap().into()),
        Some(Error::Unavailable)
    );
    expect!(
        community_error(&public, |c, dir| c.global_status_file =
            write(dir, "status", b"not a signed status")),
        Some(Error::Refused)
    );
    expect!(
        community_error(&public, |c, _| c.minimum_global_epoch = 99),
        Some(Error::Refused)
    );
    expect!(
        community_error(&public, |c, _| c.minimum_global_revision = 99),
        Some(Error::Refused)
    );
    expect!(
        community_error(&public, |c, dir| c.signing_seed_file =
            write(dir, "seed", b"too short")),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, dir| c.signing_seed_file =
            dir.join("absent").to_str().unwrap().into()),
        Some(Error::Unavailable)
    );
    // The global signing seed would make the two services share one key.
    expect!(
        community_error(&public, |c, dir| c.signing_seed_file =
            write(dir, "seed", &[4; 32])),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, dir| c.rulebook_file =
            dir.join("absent").to_str().unwrap().into()),
        Some(Error::Unavailable)
    );
    expect!(
        community_error(&public, |c, dir| c.rulebook_file =
            write(dir, "rules", b"{")),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, dir| c.schema_file =
            dir.join("absent").to_str().unwrap().into()),
        Some(Error::Unavailable)
    );
    expect!(
        community_error(&public, |c, dir| c.schema_file = write(dir, "schema", b"{")),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, dir| c.voucher_public_key_file =
            dir.join("absent").to_str().unwrap().into()),
        Some(Error::Unavailable)
    );
    expect!(
        community_error(&public, |c, dir| c.voucher_public_key_file =
            write(dir, "voucher", b"too short")),
        Some(Error::Invalid)
    );
    expect!(
        community_error(&public, |c, _| c.global_gates = vec!["Not A Gate!".into()]),
        Some(Error::Invalid)
    );
}
