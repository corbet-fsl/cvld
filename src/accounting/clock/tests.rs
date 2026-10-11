use super::*;

struct Source(AtomicU64);
impl Clock for Source {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[test]
fn native_interior_observation_fences_all_later_host_clock_reads() {
    let source = Arc::new(Source(AtomicU64::new(10)));
    let runtime = AccountRuntime::new(source.clone(), 10, 1024, "period".into()).unwrap();
    source.0.store(30, Ordering::SeqCst);
    assert_eq!(runtime.native_time(), 30);
    source.0.store(25, Ordering::SeqCst);
    // Host publication cannot release an answer below the native observation.
    assert_eq!(Clock::now(&runtime), u64::MAX);
    assert_eq!(runtime.floor(), 30);
    source.0.store(35, Ordering::SeqCst);
    assert!(matches!(runtime.observe(), Err(Error::Unavailable)));
    assert_eq!(runtime.native_time(), 0);
    assert_eq!(Clock::now(&runtime), u64::MAX);
}

#[test]
fn zero_out_of_range_and_restart_below_durable_floor_refuse() {
    for value in [0, 1u64 << 53, u64::MAX] {
        let source = Arc::new(Source(AtomicU64::new(value)));
        assert!(matches!(
            AccountRuntime::new(source, 0, 1024, "period".into()),
            Err(Error::Unavailable)
        ));
    }
    let source = Arc::new(Source(AtomicU64::new(19)));
    assert!(matches!(
        AccountRuntime::new(source, 20, 1024, "period".into()),
        Err(Error::Unavailable)
    ));
    let source = Arc::new(Source(AtomicU64::new((1u64 << 53) - 1)));
    let runtime = AccountRuntime::new(source.clone(), 20, 1024, "period".into()).unwrap();
    source.0.store(1u64 << 53, Ordering::SeqCst);
    assert!(matches!(runtime.observe(), Err(Error::Unavailable)));
    source.0.store((1u64 << 53) - 1, Ordering::SeqCst);
    assert_eq!(Clock::now(&runtime), u64::MAX);
}

#[test]
fn shutdown_fence_never_becomes_a_new_clock_lease() {
    let source = Arc::new(Source(AtomicU64::new(10)));
    let runtime = AccountRuntime::new(source.clone(), 10, 1024, "period".into()).unwrap();
    runtime.fence();
    runtime.fence();
    source.0.store(20, Ordering::SeqCst);
    assert!(matches!(runtime.observe(), Err(Error::Unavailable)));
    assert_eq!(runtime.floor(), 10);
    assert_eq!(runtime.native_time(), 0);
    assert_eq!(Clock::now(&runtime), u64::MAX);
}
