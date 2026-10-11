//! Native account composition and its caller-owned scoped durable storage.
pub(crate) mod clock;
mod config;
pub(crate) mod storage;
pub use config::{AccountConfig, ArtifactFiles, NativeExecution, VerificationLimits};
