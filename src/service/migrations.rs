//! Complete server-owned community migration history.
use cmty::cplc::crbk;
use cmty::{cgts, cmbr, cplc};

/// Original contiguous community migration history, including host-owned tables.
/// Apply it to every newly opened database handle, including an existing file,
/// before using scoped application stores. Reapplication validates the durable
/// history and initializes that handle's table allowlist.
pub fn community_migrations() -> Vec<crlt::Migration<'static>> {
    let mut schemas = cmbr::SCHEMAS.to_vec();
    schemas.extend([
        ("cgts", cgts::SCHEMA),
        ("crbk", crbk::SCHEMA),
        ("cplc", cplc::SCHEMA),
        ("csgn", csgn::SCHEMA),
        ("cpsd", cmty::storage::SCHEMA),
        ("service", crate::identity::SCHEMA),
        ("global-trust", crate::global_trust::SCHEMA),
        ("cmbr-device-keys", cmbr::DEVICE_KEYS_SCHEMA),
        ("payment-operations", crate::payments::state::SCHEMA),
    ]);
    schemas
        .iter()
        .enumerate()
        .map(|(i, (name, sql))| crlt::Migration::new(i as u32 + 1, name, sql))
        .collect()
}
