//! cvld: the permanent door. Domain decisions belong to its composed facades.
#![forbid(unsafe_code)]
#[cfg(all(feature = "development-gate", not(debug_assertions)))]
compile_error!("development-gate is forbidden in release builds");

pub mod api;
mod auth;
pub mod cli;
mod community;
mod community_actions;
pub mod config;
pub mod error;
mod global;
mod global_trust;
mod identity;
pub mod mcp;
pub mod service;

#[cfg(test)]
extern crate self as cvld;
