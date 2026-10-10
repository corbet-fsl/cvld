#![cfg(feature = "server")]
mod payment_support;
use cvld::payments::{self, *};
use payment_support::*;
use std::sync::{Arc, atomic::Ordering};

#[path = "payment_state/cancellation.rs"]
mod cancellation;
#[path = "payment_state/concurrency.rs"]
mod concurrency;
#[path = "payment_state/configuration.rs"]
mod configuration;
#[path = "payment_state/guards.rs"]
mod guards;
#[path = "payment_state/privacy.rs"]
mod privacy;
#[path = "payment_state/replay.rs"]
mod replay;
