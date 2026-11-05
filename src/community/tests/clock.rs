//! The membership clock under the door's operation time (journey rows 0 and 18).
//!
//! The door captures a request's operation time when it authorizes the request, then waits for the
//! body, the request guard and the community lock. Meanwhile another request's authentication samples
//! the membership clock live. cmbr keeps one observation floor per facade and refuses permanently
//! (`Unavailable`) after any backwards observation, so a request that waited behind a later
//! observation must not show cmbr its older operation time.
use super::*;
use crate::test_support::{NOW, TestClock};
use std::sync::atomic::AtomicU64;

const COMMUNITY: &str = "membership-clock";
type Membership = cmbr::Membership<cmbr::LibsqlStorage, CommunityAuthority, CommunityClock>;

async fn membership(clock: Arc<TestClock>) -> (tempfile::TempDir, crlt::Db, Membership) {
    let directory = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!(
            "file://{}",
            directory.path().join("membership.db").display()
        ),
        "",
    ))
    .await
    .unwrap();
    let migrations: Vec<_> = cmbr::SCHEMAS
        .iter()
        .chain([
            &("device-registry", cmbr::DEVICE_REGISTRY_SCHEMA),
            &("device-pairing", cmbr::DEVICE_PAIRING_SCHEMA),
            &("clbs-scope", cmty::cgts::legal_storage::SCOPE_SCHEMA),
        ])
        .enumerate()
        .map(|(index, (name, sql))| crlt::Migration::new(index as u32 + 1, name, sql))
        .collect();
    db.migrate(&migrations).await.unwrap();
    let authority = CommunityAuthority::new(COMMUNITY, clock.clone(), 4).unwrap();
    let membership = cmbr::Membership::new(
        &db,
        cmbr::LibsqlStorage::new(&db, COMMUNITY).unwrap(),
        cmbr::Config {
            pending_days: 2,
            membership_action: "membership".into(),
            release_period: Default::default(),
            lease_months: 12,
            rp_id: "members.example.test".into(),
            origins: vec![ckyh::Url::parse("https://members.example.test").unwrap()],
        },
        authority,
        CommunityClock::new(clock),
    )
    .unwrap();
    (directory, db, membership)
}

/// A live read: what `authorize` does when it authenticates a device-key session.
async fn live(membership: &Membership) -> cmbr::Result<bool> {
    membership.is_handle_available("member_one", &[]).await
}
/// A handler read at the operation time its request was authorized at.
async fn at(now: u64, membership: &Membership) -> cmbr::Result<bool> {
    crate::service::at(now, membership.is_handle_available("member_one", &[])).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_that_waited_behind_a_later_observation_keeps_the_membership_available() {
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let (_directory, _db, membership) = membership(clock.clone()).await;
    // Request A is authorized at NOW. While it waits for the door the second turns and
    // request B authenticates: a live sample at NOW + 1.
    clock.set(NOW + 1);
    assert_eq!(live(&membership).await, Ok(true));
    // A's handler then runs at its own operation time, NOW.
    assert_eq!(at(NOW, &membership).await, Ok(true));
    // The facade stays available for everyone after it.
    assert_eq!(live(&membership).await, Ok(true));
    assert_eq!(at(NOW + 1, &membership).await, Ok(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operation_times_finishing_out_of_order_keep_the_membership_available() {
    let clock = Arc::new(TestClock(AtomicU64::new(NOW + 2)));
    let (_directory, _db, membership) = membership(clock.clone()).await;
    // Requests authorized at NOW + 2, NOW and NOW + 1 run in that order.
    for now in [NOW + 2, NOW, NOW + 1] {
        assert_eq!(at(now, &membership).await, Ok(true), "operation time {now}");
    }
    assert_eq!(live(&membership).await, Ok(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_clock_that_goes_back_still_refuses_the_membership_for_good() {
    let clock = Arc::new(TestClock(AtomicU64::new(NOW + 5)));
    let (_directory, _db, membership) = membership(clock.clone()).await;
    assert_eq!(live(&membership).await, Ok(true));
    // The source itself goes back: no operation time may hide that, live or scoped.
    clock.set(NOW);
    assert_eq!(at(NOW + 5, &membership).await, Err(cmbr::Error::Unavailable));
    assert_eq!(live(&membership).await, Err(cmbr::Error::Unavailable));
    // A later correction does not clear it (cmbr CONTRACT: the floor refuses for good).
    clock.set(NOW + 10);
    assert_eq!(live(&membership).await, Err(cmbr::Error::Unavailable));
    assert_eq!(at(NOW + 10, &membership).await, Err(cmbr::Error::Unavailable));
}
