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
        ("account-current", crate::accounting::storage::SCHEMA),
        ("cmbr-creation", cmbr::CREATION_SCHEMA),
        ("cmbr-role-redemption", cmbr::ROLE_REDEMPTION_SCHEMA),
        ("ohttp-replay", crate::ohttp::SCHEMA),
    ]);
    schemas
        .iter()
        .enumerate()
        .map(|(i, (name, sql))| crlt::Migration::new(i as u32 + 1, name, sql))
        .collect()
}

/// Original contiguous global migration history, including host-owned tables.
/// Apply it to every newly opened database handle before using scoped stores.
pub fn global_migrations() -> Vec<crlt::Migration<'static>> {
    vec![
        crlt::Migration::new(1, "global", cgbl::storage::SCHEMA),
        crlt::Migration::new(2, "signing", csgn::SCHEMA),
        crlt::Migration::new(3, "passkeys", ckyh::LIBSQL_SCHEMA),
        crlt::Migration::new(4, "service", crate::identity::SCHEMA),
        crlt::Migration::new(5, "passport-challenges", cpsd::storage::libsql::SCHEMA),
        crlt::Migration::new(
            6,
            "passport-issuance",
            cpsd::storage::libsql::ISSUANCE_SCHEMA,
        ),
        crlt::Migration::new(
            7,
            "passport-owners",
            cpsd::storage::libsql::ISSUANCE_UNIQUENESS_SCHEMA,
        ),
        crlt::Migration::new(8, "contact-operations", crate::contact_gates::state::SCHEMA),
        crlt::Migration::new(
            9,
            "contact-comparison-keys",
            crate::contact_gates::state::BINDING_SCHEMA,
        ),
        crlt::Migration::new(10, "ohttp-replay", crate::ohttp::SCHEMA),
    ]
}
