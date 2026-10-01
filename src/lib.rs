//! cvld: the permanent door. Domain decisions belong to its composed facades.
#![forbid(unsafe_code)]
#[cfg(all(feature = "development-gate", not(debug_assertions)))]
compile_error!("development-gate is forbidden in release builds");

#[cfg(feature = "server")]
pub mod api;
#[cfg(feature = "server")]
mod auth;
#[cfg(feature = "server")]
pub mod cli;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
mod community;
#[cfg(feature = "server")]
mod community_actions;
#[cfg(feature = "server")]
pub mod config;
pub mod error;
#[cfg(feature = "server")]
mod global;
#[cfg(feature = "server")]
mod global_trust;
#[cfg(feature = "server")]
mod identity;
#[cfg(feature = "server")]
pub mod mcp;
#[cfg(feature = "server")]
pub mod service;

#[cfg(test)]
extern crate self as cvld;
