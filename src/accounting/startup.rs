//! Startup owns native cleanup before there is a usable Door to shut down.
use super::clock::AccountRuntime;
use crate::error::{Error, Result};
use std::sync::Arc;

pub(crate) struct Startup {
    runtime: Option<Arc<AccountRuntime>>,
    shutdown: Option<cmty::cgts::AccountShutdown>,
    armed: bool,
}
impl Startup {
    pub(crate) fn new(
        runtime: Option<Arc<AccountRuntime>>,
        shutdown: Option<cmty::cgts::AccountShutdown>,
    ) -> Self {
        Self {
            runtime,
            shutdown,
            armed: true,
        }
    }
    pub(crate) async fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            if let Some(runtime) = &self.runtime {
                runtime.fence();
            }
            if let Some(shutdown) = &self.shutdown {
                shutdown
                    .shutdown()
                    .await
                    .map_err(Error::Unavailable.redact())?;
            }
        }
        self.armed = false;
        result
    }
}
impl Drop for Startup {
    fn drop(&mut self) {
        if self.armed {
            if let Some(runtime) = &self.runtime {
                runtime.fence();
            }
            if let Some(shutdown) = &self.shutdown {
                // Only START the maintained shared join. Dropping a factory
                // future cannot promise its caller awaited native completion.
                let _ = shutdown.begin_shutdown();
            }
        }
    }
}
