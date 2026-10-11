//! Caller-retained lifetime for native construction before a Door exists.
use super::{
    clock::AccountRuntime,
    config::{AccountConfig, Service},
    enrollment::Enrollment,
};
use crate::{
    error::{Error, Result},
    service::Clock,
};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

type Parts = (Service, Enrollment, Arc<AccountRuntime>);
type Cancel = Box<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct Cancellations {
    closed: bool,
    owned: Vec<Cancel>,
}
pub(crate) struct Cancellation(Mutex<Cancellations>);
impl Cancellation {
    fn new() -> Self {
        Self(Mutex::new(Cancellations::default()))
    }
    pub(crate) fn register(&self, cancel: impl Fn() + Send + Sync + 'static) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        // Registration and cancellation share one lock. A late real owner is
        // withdrawn immediately, even if shutdown preceded its construction.
        if state.closed {
            cancel();
        } else {
            state.owned.push(Box::new(cancel));
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.0.lock().map_err(Error::Unavailable.redact())?.closed {
            Err(Error::Unavailable)
        } else {
            Ok(())
        }
    }
    fn cancel(&self) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        state.closed = true;
        for cancel in &state.owned {
            cancel();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Completion {
    Pending,
    Ready,
    Joined(bool),
}
struct Slot {
    result: Option<Result<Parts>>,
    taken: bool,
    cancelled: bool,
}
struct Task {
    cancellation: Cancellation,
    slot: Mutex<Slot>,
    handoff: Condvar,
    worker: Mutex<Option<JoinHandle<()>>>,
    phase: tokio::sync::watch::Sender<Completion>,
}
impl Task {
    fn start(
        build: impl FnOnce(&Cancellation) -> Result<Parts> + Send + 'static,
    ) -> Result<Arc<Self>> {
        let (phase, _) = tokio::sync::watch::channel(Completion::Pending);
        let task = Arc::new(Self {
            cancellation: Cancellation::new(),
            slot: Mutex::new(Slot {
                result: None,
                taken: false,
                cancelled: false,
            }),
            handoff: Condvar::new(),
            worker: Mutex::new(None),
            phase,
        });
        let owner = task.clone();
        let worker = std::thread::Builder::new()
            .name("account-construction".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    owner.cancellation.check()?;
                    build(&owner.cancellation)
                }))
                .unwrap_or(Err(Error::Unavailable));
                // This SAME native builder owns the result until handoff or
                // cancellation. Unclaimed service/store drops stay here.
                let mut slot = owner.slot.lock().unwrap_or_else(|p| p.into_inner());
                slot.result = Some(result);
                owner.phase.send_replace(Completion::Ready);
                while !slot.taken && !slot.cancelled {
                    slot = owner.handoff.wait(slot).unwrap_or_else(|p| p.into_inner());
                }
                drop(slot.result.take());
            })
            .map_err(Error::Unavailable.redact())?;
        *task.worker.lock().unwrap_or_else(|p| p.into_inner()) = Some(worker);
        Ok(task)
    }
    fn cancel(&self) {
        self.cancellation.cancel();
        let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        slot.cancelled = true;
        self.handoff.notify_all();
    }
    async fn join(&self) -> Result<()> {
        loop {
            let joined = {
                let mut worker = self.worker.lock().unwrap_or_else(|p| p.into_inner());
                if worker.as_ref().is_some_and(JoinHandle::is_finished) {
                    // The native body and its result/drop ownership have ended.
                    // std documents is_finished -> join as a nonblocking join;
                    // only the brief final thread-local teardown may remain.
                    let joined = worker.take().expect("finished native owner").join().is_ok();
                    self.phase.send_replace(Completion::Joined(joined));
                    Some(joined)
                } else {
                    match *self.phase.borrow() {
                        Completion::Joined(joined) => Some(joined),
                        _ => None,
                    }
                }
            };
            if let Some(joined) = joined {
                return if joined {
                    Ok(())
                } else {
                    Err(Error::Unavailable)
                };
            }
            // Keep the actual handle and original DB runtime alive. This never
            // creates a fallible second join thread or renews an owner deadline.
            tokio::task::yield_now().await;
        }
    }
    async fn result(&self) -> Result<Parts> {
        let mut receiver = self.phase.subscribe();
        loop {
            let phase = *receiver.borrow_and_update();
            match phase {
                Completion::Ready => {
                    let result = {
                        let mut slot = self.slot.lock().map_err(Error::Unavailable.redact())?;
                        if slot.cancelled {
                            return Err(Error::Unavailable);
                        }
                        let result = slot.result.take().ok_or(Error::Unavailable)?;
                        slot.taken = true;
                        self.handoff.notify_all();
                        result
                    };
                    self.join().await?;
                    self.cancellation.check()?;
                    return result;
                }
                Completion::Joined(_) => return Err(Error::Unavailable),
                Completion::Pending => {}
            }
            receiver
                .changed()
                .await
                .map_err(Error::Unavailable.redact())?;
        }
    }
    async fn shutdown(&self) -> Result<()> {
        self.cancel();
        self.join().await
    }
}
struct Waiting {
    task: Arc<Task>,
    armed: bool,
}
impl Drop for Waiting {
    fn drop(&mut self) {
        if self.armed {
            self.task.cancel();
        }
    }
}
#[derive(Default)]
struct Registry {
    closed: bool,
    tasks: Vec<Arc<Task>>,
}
struct Inner(Mutex<Registry>);
impl Drop for Inner {
    fn drop(&mut self) {
        let registry = self.0.get_mut().unwrap_or_else(|p| p.into_inner());
        for task in &registry.tasks {
            task.cancel();
        }
        // Drain is initiated; only a retained async owner can await actual join.
    }
}

/// Host-only construction lifetime, not a member capability or wire value.
/// Retain before polling a factory and await shutdown before its original
/// Tokio/DB runtime is torn down, including after abandoning the factory.
#[derive(Clone)]
#[must_use = "retain before factory polling and await shutdown before runtime teardown"]
pub struct NativeConstruction(Arc<Inner>);
impl Default for NativeConstruction {
    fn default() -> Self {
        Self::new()
    }
}
impl NativeConstruction {
    /// Create an open group before polling any of its community factories.
    /// Keep a clone until explicit shutdown finishes and the original runtime
    /// can safely close. Dropping a group starts cancellation/drain, not a join.
    pub fn new() -> Self {
        Self(Arc::new(Inner(Mutex::new(Registry::default()))))
    }
    /// Close intake and start cancellation of every retained construction.
    /// This does not join a builder; await `shutdown` before runtime teardown.
    pub fn begin_shutdown(&self) -> Result<()> {
        let tasks = {
            let mut registry = self.0.0.lock().map_err(Error::Unavailable.redact())?;
            registry.closed = true;
            registry.tasks.clone()
        };
        // Cancel all actual owners before waiting for any one construction.
        for task in &tasks {
            task.cancel();
        }
        Ok(())
    }
    /// Permanently close this group, cancel every registered native owner and
    /// await all construction joins before the host tears down its DB runtime.
    /// Cancelled waiters leave those same joins owned for a later retry.
    pub async fn shutdown(&self) -> Result<()> {
        self.begin_shutdown()?;
        let tasks = self
            .0
            .0
            .lock()
            .map_err(Error::Unavailable.redact())?
            .tasks
            .clone();
        let mut failed = false;
        for task in tasks {
            failed |= task.shutdown().await.is_err();
        }
        if failed {
            Err(Error::Unavailable)
        } else {
            Ok(())
        }
    }
    pub(crate) async fn build(
        &self,
        config: AccountConfig,
        db: crlt::Db,
        community: String,
        keys: cblc::accounting_ledger::AdmissionKeyReconciliation,
        clock: Arc<dyn Clock>,
        runtime: tokio::runtime::Handle,
    ) -> Result<Parts> {
        let task = {
            let mut registry = self.0.0.lock().map_err(Error::Unavailable.redact())?;
            if registry.closed {
                return Err(Error::Unavailable);
            }
            // Register under the shutdown lock before the first async wait.
            let task = Task::start(move |cancellation| {
                config.build(&db, &community, keys, clock, runtime, cancellation)
            })?;
            registry.tasks.push(task.clone());
            task
        };
        let mut waiting = Waiting {
            task: task.clone(),
            armed: true,
        };
        let result = task.result().await;
        if result.is_err() {
            task.shutdown().await?;
        }
        waiting.armed = false;
        result
    }
}

#[cfg(test)]
mod tests;
