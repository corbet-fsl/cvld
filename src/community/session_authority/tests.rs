use super::*;
use crate::service::Clock;
use std::{collections::HashMap, sync::atomic::AtomicU64};

struct Time(AtomicU64);
impl Clock for Time {
    fn now(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}
fn runtime() -> (Arc<AccountRuntime>, Arc<Time>) {
    let clock = Arc::new(Time(AtomicU64::new(10)));
    (
        Arc::new(AccountRuntime::new(clock.clone(), 10, 1024, "period".into()).unwrap()),
        clock,
    )
}

#[test]
fn removing_or_replacing_actual_session_owner_invalidates_retained_worker_lease() {
    let (runtime, _) = runtime();
    let mut sessions = HashMap::from([("session", Owner::default())]);
    let original = sessions["session"].lease(10, 20, runtime.clone());
    assert!(original.check(10).is_ok());
    sessions.insert("session", Owner::default());
    assert!(original.check(10).is_err());
    let replacement = sessions["session"].lease(10, 20, runtime);
    assert!(replacement.check(10).is_ok());
    sessions.remove("session");
    assert!(replacement.check(10).is_err());
}

#[test]
fn cancellation_retains_capability_but_cannot_keep_a_removed_session_alive() {
    let (runtime, _) = runtime();
    let owner = Owner::default();
    let request = owner.lease(10, 20, runtime);
    let worker = request.clone();
    drop(request);
    assert!(worker.check(10).is_ok());
    drop(owner);
    assert!(worker.check(10).is_err());
}

#[test]
fn session_bounds_crossed_end_and_native_shutdown_refuse_a_plain_later_second_does_not() {
    let (runtime, clock) = runtime();
    let owner = Owner::default();
    let lease = owner.lease(10, 20, runtime.clone());
    assert_eq!(lease.valid_until(), 20);
    assert!(lease.check(9).is_err());
    assert!(lease.check(20).is_err());
    // Evaluated at the observed second: a later live second without a boundary commits.
    clock.0.store(11, Ordering::Release);
    assert!(lease.check(10).is_ok());
    assert!(lease.check(11).is_ok());
    // An observation after the live clock (a regressed clock) refuses.
    assert!(lease.check(12).is_err());
    // The session's own end in (observed, now] refuses.
    clock.0.store(20, Ordering::Release);
    assert!(lease.check(19).is_err());
    let (runtime, _) = self::runtime();
    let lease = owner.lease(10, 20, runtime.clone());
    assert!(lease.check(10).is_ok());
    runtime.fence();
    assert!(lease.check(10).is_err());
}
