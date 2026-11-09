//! cvld-client: the client-facing contract of the cvld door — wire types, the
//! generated-contract client and its HTTP/browser/OHTTP runtimes, address rules,
//! the blind creation-token protocol and device-session messages. It links none
//! of the server; `cvld` depends on it and re-exports it.
#![forbid(unsafe_code)]
#[cfg(all(
    any(feature = "development-gate", feature = "development-gate-client"),
    not(debug_assertions)
))]
compile_error!("development-gate is forbidden in release builds");

pub mod address;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub mod creation_token;
pub mod device_session;
pub mod error;
