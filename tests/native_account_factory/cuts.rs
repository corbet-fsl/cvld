use super::*;
use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::sync::Notify;

pub(super) struct ObservedClock {
    count: AtomicU64,
    cut: Option<(u64, u64)>,
    pause_native: bool,
    paused: AtomicBool,
    reached: Notify,
    release: (Mutex<bool>, Condvar),
}
impl ObservedClock {
    pub fn steady() -> Self {
        Self::new(None, false)
    }
    fn new(cut: Option<(u64, u64)>, pause_native: bool) -> Self {
        Self {
            count: AtomicU64::new(0),
            cut,
            pause_native,
            paused: AtomicBool::new(false),
            reached: Notify::new(),
            release: (Mutex::new(false), Condvar::new()),
        }
    }
    pub fn calls(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
    fn release(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }
}
// An assertion failure must never leave the actual native constructor blocked.
struct Release(Arc<ObservedClock>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
impl Clock for ObservedClock {
    fn now(&self) -> u64 {
        let call = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        // Pause the actual application native construction thread at its live
        // owner observation, not a fake verifier or an accepting storage hook.
        if self.pause_native
            && std::thread::current().name() == Some("account-construction")
            && !self.paused.swap(true, Ordering::SeqCst)
        {
            self.reached.notify_one();
            let (lock, ready) = &self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = ready.wait(released).unwrap();
            }
        }
        self.cut
            .filter(|(sample, _)| call >= *sample)
            .map_or(NOW, |(_, now)| now)
    }
}
async fn final_sample(future_epoch: bool) -> u64 {
    let fixture = Fixture::new().await;
    fixture.seed_policy(future_epoch).await;
    let clock = Arc::new(ObservedClock::steady());
    let owner = NativeConstruction::new();
    let door =
        Door::community_with_construction(fixture.config.clone(), clock.clone(), owner.clone())
            .await
            .unwrap();
    let last = clock.calls();
    fixture.check_feed(&fixture.feed(&door).await);
    door.shutdown_accounts().await.unwrap();
    owner.shutdown().await.unwrap();
    last
}
async fn refused_final_cut(future_epoch: bool, expires: bool) {
    let last = final_sample(future_epoch).await;
    let fixture = Fixture::new().await;
    fixture.seed_policy(future_epoch).await;
    let late = if expires {
        fixture.context_deadline
    } else {
        NOW + 1
    };
    let clock = Arc::new(ObservedClock::new(Some((last, late)), false));
    let owner = NativeConstruction::new();
    let result =
        Door::community_with_construction(fixture.config.clone(), clock.clone(), owner.clone())
            .await;
    assert!(matches!(result, Err(cvld::error::Error::Reconcile)));
    // Any earlier native/publication refusal is not this final exposure test.
    assert_eq!(clock.calls(), last);
    owner.shutdown().await.unwrap();
    let rows = fixture.native_rows().await;
    assert!(rows.iter().any(|(key, _)| key == b"settlement-mode:v1"));
    // The original Policy signed output and native mode really committed before
    // the cut. The error is uncertainty, not a claim that they rolled back.
    use cmty::cplc::Storage;
    let db = fixture.db().await;
    let state = cmty::cplc::LibsqlStore::new(&db, "alpha")
        .unwrap()
        .load()
        .await
        .unwrap()
        .unwrap();
    let state = serde_json::to_value(state).unwrap();
    assert!(
        state["balance"]["cose"]
            .as_array()
            .is_some_and(|bytes| !bytes.is_empty())
    );
    // Reconciliation requires a new honest observation, never rolling the
    // same native clock backwards to manufacture a usable result.
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exclusive_context_expiry_after_real_publication_withholds_the_factory() {
    refused_final_cut(false, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_scheduled_policy_crossing_at_final_exposure_withholds_the_factory() {
    refused_final_cut(true, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoning_actual_native_construction_retains_and_joins_its_owner() {
    let fixture = Fixture::new().await;
    fixture.seed_policy(false).await;
    let clock = Arc::new(ObservedClock::new(None, true));
    let _release_on_failure = Release(clock.clone());
    let owner = NativeConstruction::new();
    let config = fixture.config.clone();
    let active = owner.clone();
    let native_clock = clock.clone();
    let factory = tokio::spawn(async move {
        Door::community_with_construction(config, native_clock, active).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(60), clock.reached.notified())
        .await
        .unwrap();
    assert!(clock.paused.load(Ordering::SeqCst));
    factory.abort();
    match factory.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("abandoned factory must not return a usable door"),
    }
    owner.begin_shutdown().unwrap();
    let joining = owner.shutdown();
    tokio::pin!(joining);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut joining)
            .await
            .is_err()
    );
    clock.release();
    tokio::time::timeout(std::time::Duration::from_secs(60), joining)
        .await
        .unwrap()
        .unwrap();
    // Native construction was paused before initial installation. It cannot
    // leak a usable daily configuration or a public success on cancellation.
    assert!(
        !fixture
            .native_rows()
            .await
            .iter()
            .any(|(key, _)| key == b"settlement-mode:v1")
    );
    assert!(matches!(
        Door::community_with_construction(
            fixture.config.clone(),
            Arc::new(ObservedClock::steady()),
            owner.clone(),
        )
        .await,
        Err(cvld::error::Error::Unavailable)
    ));
    owner.shutdown().await.unwrap();
}
