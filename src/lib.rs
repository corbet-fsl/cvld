//! cvld: the permanent door. Domain decisions belong to its composed facades.
#![forbid(unsafe_code)]
#[cfg(all(
    any(feature = "development-gate", feature = "development-gate-client"),
    not(debug_assertions)
))]
compile_error!("development-gate is forbidden in release builds");

#[cfg(feature = "server")]
pub mod accounting;
#[cfg(feature = "server")]
pub mod api;
#[cfg(feature = "server")]
mod auth;
#[cfg(feature = "server")]
mod bucket;
#[cfg(feature = "server")]
pub mod cli;
#[cfg(feature = "server")]
mod community;
#[cfg(feature = "server")]
mod community_actions;
#[cfg(feature = "server")]
pub mod config;
#[cfg(feature = "server")]
pub mod contact_gates;
#[cfg(feature = "server")]
pub mod creation_token;
#[cfg(feature = "server")]
mod device_registry;
#[cfg(feature = "server")]
pub mod error;
#[cfg(feature = "server")]
mod genesis_store;
#[cfg(feature = "server")]
mod global;
#[cfg(feature = "server")]
mod global_trust;
#[cfg(feature = "server")]
pub mod hold;
#[cfg(feature = "server")]
pub mod hosts;
#[cfg(feature = "server")]
pub mod hub;
#[cfg(feature = "server")]
mod identity;
#[cfg(feature = "server")]
mod join_publication_store;
#[cfg(feature = "server")]
pub mod mcp;
#[cfg(feature = "server")]
mod ohttp;
#[cfg(feature = "server")]
pub mod payments;
#[cfg(feature = "server")]
pub mod purge;
#[cfg(feature = "server")]
pub mod registry;
#[cfg(feature = "server")]
pub mod service;
#[cfg(feature = "server")]
mod stamp_uses;
#[cfg(feature = "server")]
mod step_up;

// The client-facing contract lives in `cvld-client`; its modules keep their `cvld::` paths.
#[cfg(feature = "client")]
pub use cvld_client::client;
#[cfg(all(feature = "client", not(feature = "server")))]
pub use cvld_client::creation_token;
#[cfg(not(feature = "server"))]
pub use cvld_client::error;
pub use cvld_client::{address, device_session};

#[cfg(test)]
extern crate self as cvld;

#[cfg(all(test, feature = "server"))]
#[path = "../tests/support/mod.rs"]
mod test_support;

#[cfg(all(test, feature = "server"))]
#[path = "../tests/payment_support/mod.rs"]
mod payment_test_support;
