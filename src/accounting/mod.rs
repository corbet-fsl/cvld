//! Native account composition and its caller-owned scoped durable storage.
pub(crate) mod build;
pub(crate) mod clock;
pub use build::NativeConstruction;
mod config;
pub(crate) mod startup;
pub(crate) mod storage;
pub use config::{AccountConfig, ArtifactFiles, NativeExecution, VerificationLimits};
