use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

async fn open(url: &str) -> Db {
    let db = Db::open(crlt::Config::new(url, "")).await.unwrap();
    db.migrate(&crate::service::community_migrations())
        .await
        .unwrap();
    db
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_scoped_transactions_rollback_isolate_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("accounts.db").display());
    let db = open(&url).await;
    let runtime = Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut alpha = Store::new(&db, "alpha", runtime.clone()).unwrap();
        let mut beta = Store::new(&db, "beta", runtime).unwrap();
        let mut tx = alpha.transaction().unwrap();
        tx.put(b"winner", &7u64).unwrap();
        drop(tx);
        let mut tx = alpha.transaction().unwrap();
        assert_eq!(tx.get::<u64>(b"winner").unwrap(), None);
        tx.put(b"winner", &9u64).unwrap();
        tx.commit().unwrap();
        let mut tx = beta.transaction().unwrap();
        assert_eq!(tx.get::<u64>(b"winner").unwrap(), None);
        tx.put(b"winner", &11u64).unwrap();
        tx.commit().unwrap();
        let mut tx = alpha.transaction().unwrap();
        assert_eq!(tx.get::<u64>(b"winner").unwrap(), Some(9));
        tx.delete(b"winner").unwrap();
        tx.rollback().unwrap();
    })
    .await
    .unwrap();
    let reopened = open(&url).await;
    let runtime = Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut alpha = Store::new(&reopened, "alpha", runtime.clone()).unwrap();
        let mut beta = Store::new(&reopened, "beta", runtime).unwrap();
        assert_eq!(
            alpha.transaction().unwrap().get::<u64>(b"winner").unwrap(),
            Some(9)
        );
        assert_eq!(
            beta.transaction().unwrap().get::<u64>(b"winner").unwrap(),
            Some(11)
        );
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_range_is_half_open_complete_across_pages_and_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("range.db").display());
    let db = open(&url).await;
    let runtime = Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut store = Store::new(&db, "range", runtime).unwrap();
        let mut tx = store.transaction().unwrap();
        for index in 0..1002u32 {
            tx.put(&index.to_be_bytes(), &index).unwrap();
        }
        tx.commit().unwrap();
        let mut tx = store.transaction().unwrap();
        let records: Vec<(Vec<u8>, u32)> = tx
            .current_range(&0u32.to_be_bytes(), &1002u32.to_be_bytes(), 1002)
            .unwrap();
        assert_eq!(records.len(), 1002);
        for (index, (key, value)) in records.into_iter().enumerate() {
            assert_eq!(key, (index as u32).to_be_bytes());
            assert_eq!(value, index as u32);
        }
        let records: Vec<(Vec<u8>, u32)> = tx
            .current_range(&1u32.to_be_bytes(), &3u32.to_be_bytes(), 100)
            .unwrap();
        assert_eq!(
            records.iter().map(|(_, value)| *value).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            tx.current_range::<u32>(&0u32.to_be_bytes(), &1002u32.to_be_bytes(), 1)
                .unwrap()
                .len(),
            1
        );
        assert!(tx.current_range::<u32>(b"a", b"z", 0).is_err());
        assert!(tx.current_range::<u32>(b"a", b"z", (1 << 20) + 2).is_err());
        assert!(tx.current_range::<u32>(b"z", b"a", 1).is_err());
        tx.rollback().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_deadline_is_live_under_the_write_lock_and_clock_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("deadline.db").display());
    let db = open(&url).await;
    let runtime = Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut store = Store::new(&db, "deadline", runtime).unwrap();
        let now = Arc::new(AtomicU64::new(10));
        let clock = || now.load(Ordering::SeqCst);
        let deadline = CommitDeadline::new(&clock, 10, 20);
        let mut tx = store.transaction().unwrap();
        tx.put(b"winner", &7u64).unwrap();
        now.store(20, Ordering::SeqCst);
        assert!(matches!(tx.commit_before(&deadline), Err(Error::Expired)));
        let mut tx = store.transaction().unwrap();
        assert_eq!(tx.get::<u64>(b"winner").unwrap(), None);
        assert_eq!(tx.get::<u64>(b"clock").unwrap(), None);
        tx.rollback().unwrap();
        now.store(15, Ordering::SeqCst);
        let deadline = CommitDeadline::new(&clock, 15, 20);
        let mut tx = store.transaction().unwrap();
        tx.put(b"winner", &9u64).unwrap();
        tx.commit_before(&deadline).unwrap();
        let mut tx = store.transaction().unwrap();
        assert_eq!(tx.get::<u64>(b"winner").unwrap(), Some(9));
        assert_eq!(tx.get::<u64>(b"clock").unwrap(), Some(15));
        tx.rollback().unwrap();
        let rollback = CommitDeadline::new(&clock, 16, 20);
        let mut tx = store.transaction().unwrap();
        tx.put(b"winner", &11u64).unwrap();
        assert!(matches!(
            tx.commit_before(&rollback),
            Err(Error::ClockRollback)
        ));
        assert_eq!(
            store.transaction().unwrap().get::<u64>(b"winner").unwrap(),
            Some(9)
        );
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_clock_floor_is_original_strict_and_reopen_cannot_reset_it() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("clock.db").display());
    let db = open(&url).await;
    let runtime = Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut store = Store::new(&db, "clock", runtime).unwrap();
        assert!(matches!(store.durable_floor(), Err(Error::Storage)));
        let mut tx = store.transaction().unwrap();
        tx.put(b"clock", &"20").unwrap();
        tx.commit().unwrap();
        assert!(store.durable_floor().is_err());
        let clock = || 20u64;
        let deadline = CommitDeadline::new(&clock, 20, 30);
        let mut tx = store.transaction().unwrap();
        tx.put(b"winner", &7u64).unwrap();
        tx.commit_before(&deadline).unwrap();
        assert_eq!(store.durable_floor().unwrap(), 20);
    })
    .await
    .unwrap();
    let reopened = open(&url).await;
    let handle = Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut store = Store::new(&reopened, "clock", handle).unwrap();
        let floor = store.durable_floor().unwrap();
        struct BeforeRestart;
        impl crate::service::Clock for BeforeRestart {
            fn now(&self) -> u64 {
                19
            }
        }
        assert!(matches!(
            crate::accounting::clock::AccountRuntime::new(
                Arc::new(BeforeRestart),
                floor,
                1024,
                "period".into(),
            ),
            Err(crate::error::Error::Unavailable)
        ));
        assert_eq!(store.durable_floor().unwrap(), 20);
        assert_eq!(
            store.transaction().unwrap().get::<u64>(b"winner").unwrap(),
            Some(7)
        );
    })
    .await
    .unwrap();
}
