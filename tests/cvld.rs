//! All cvld integration tests in ONE test binary (one link of the whole dependency tree instead of 36).
//! Each former `tests/<name>.rs` is the module `<name>` under `tests/cases/`; its feature and platform gate
//! stays the inner `#![cfg(..)]` of that file. The shared support modules are declared once here (they are also
//! the lib's `test_support` modules, so they stay in `tests/support` and `tests/payment_support`).
//! `client_browser` is the wasm-only browser suite and stays its own target.

#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
#[path = "support/mod.rs"]
mod support;
#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
#[path = "payment_support/mod.rs"]
mod payment_support;

#[path = "cases/account_boundaries.rs"]
mod account_boundaries;
#[path = "cases/account_passkeys.rs"]
mod account_passkeys;
#[path = "cases/account_record.rs"]
mod account_record;
#[path = "cases/build_policy.rs"]
mod build_policy;
#[path = "cases/client_authenticated.rs"]
mod client_authenticated;
#[path = "cases/client_contract.rs"]
mod client_contract;
#[path = "cases/client_negative.rs"]
mod client_negative;
#[path = "cases/client_record.rs"]
mod client_record;
#[path = "cases/community_http.rs"]
mod community_http;
#[path = "cases/community_self_ban.rs"]
mod community_self_ban;
#[path = "cases/contact_boundaries.rs"]
mod contact_boundaries;
#[path = "cases/contact_gates.rs"]
mod contact_gates;
#[path = "cases/contact_routes.rs"]
mod contact_routes;
#[path = "cases/devices.rs"]
mod devices;
#[path = "cases/discoverable.rs"]
mod discoverable;
#[path = "cases/global_http.rs"]
mod global_http;
#[path = "cases/global_initial_registration.rs"]
mod global_initial_registration;
#[path = "cases/global_self_ban.rs"]
mod global_self_ban;
#[path = "cases/hub.rs"]
mod hub;
#[path = "cases/initial_creation.rs"]
mod initial_creation;
#[path = "cases/native_account_factory.rs"]
mod native_account_factory;
#[path = "cases/native_account_parameters.rs"]
mod native_account_parameters;
#[path = "cases/passkey_certificates.rs"]
mod passkey_certificates;
#[path = "cases/payment_boundaries.rs"]
mod payment_boundaries;
#[path = "cases/payment_routes.rs"]
mod payment_routes;
#[path = "cases/payment_state.rs"]
mod payment_state;
#[path = "cases/production.rs"]
mod production;
#[path = "cases/production_journey.rs"]
mod production_journey;
#[path = "cases/root_board.rs"]
mod root_board;
#[path = "cases/root_config.rs"]
mod root_config;
#[path = "cases/self_ban_status.rs"]
mod self_ban_status;
#[path = "cases/startup.rs"]
mod startup;
#[path = "cases/surfaces.rs"]
mod surfaces;
#[path = "cases/transports.rs"]
mod transports;
#[path = "cases/turso.rs"]
mod turso;
#[path = "cases/voucher_reply.rs"]
mod voucher_reply;

/// A file dropped into `tests/cases/` without a `mod` line above would silently never run.
#[test]
fn every_case_file_is_wired_into_this_binary() {
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let hub = std::fs::read_to_string(here.join("cvld.rs")).expect("read the hub");
    for entry in std::fs::read_dir(here.join("cases")).expect("tests/cases") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let name = path.file_name().expect("name").to_string_lossy().into_owned();
            assert!(hub.contains(&format!("#[path = \"cases/{name}\"]")), "tests/cases/{name} is not wired into tests/cvld.rs");
        }
    }
}
