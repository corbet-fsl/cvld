//! Complete server-owned community migration history.
use cmty::cplc::crbk;
use cmty::{cgts, cmbr, cplc};

/// Retired table of the removed FounderAdmin entitlement. Migration history is
/// immutable, so existing databases keep this entry; nothing reads or writes it.
const RETIRED_ROLE_REDEMPTION_SCHEMA: &str = "CREATE TABLE cmbr_role_redemption (
    community_id TEXT NOT NULL,
    receipt TEXT NOT NULL CHECK (length(receipt) = 64 AND NOT (receipt GLOB '*[^0-9a-f]*')),
    binding TEXT NOT NULL CHECK (length(binding) = 64 AND NOT (binding GLOB '*[^0-9a-f]*')),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    member TEXT NOT NULL CHECK (length(member) BETWEEN 1 AND 1024),
    lease_year INTEGER NOT NULL CHECK (lease_year BETWEEN 1 AND 9999),
    lease_month INTEGER NOT NULL CHECK (lease_month BETWEEN 1 AND 12),
    admitted_revision INTEGER NOT NULL CHECK (admitted_revision > 0),
    PRIMARY KEY (community_id, receipt),
    UNIQUE (community_id, member)
) WITHOUT ROWID;";

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
        ("cmbr-role-redemption", RETIRED_ROLE_REDEMPTION_SCHEMA),
        ("ohttp-replay", crate::ohttp::SCHEMA),
        ("genesis", crate::genesis_store::SCHEMA),
        ("cmbr-device-pending", cmbr::DEVICE_PENDING_SCHEMA),
        ("device-registry", crate::device_registry::SCHEMA),
        ("stamp-uses", crate::stamp_uses::SCHEMA),
        ("cmbr-device-pairing", cmbr::DEVICE_PAIRING_SCHEMA),
    ]);
    let mut migrations: Vec<crlt::Migration<'static>> = schemas
        .iter()
        .enumerate()
        .map(|(i, (name, sql))| crlt::Migration::new(i as u32 + 1, name, sql))
        .collect();
    // Community legal scope (P4b): order scope survives the store round-trip.
    // Appended last: migration history is immutable, so existing ledgers keep
    // their versions and only this new entry is applied.
    migrations.push(crlt::Migration::new(
        migrations.len() as u32 + 1,
        "clbs-scope",
        cgts::legal_storage::SCOPE_SCHEMA,
    ));
    migrations
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
        crlt::Migration::new(11, "registry", crate::registry::SCHEMA),
        crlt::Migration::new(12, "creation-tokens", crate::creation_token::SCHEMA),
        crlt::Migration::new(
            13,
            "creation-signatures",
            crate::creation_token::SIGNATURES_SCHEMA,
        ),
        crlt::Migration::new(
            14,
            "stamp-issuance",
            cpsd::storage::libsql::STAMP_ISSUANCE_SCHEMA,
        ),
        crlt::Migration::new(15, "legal-hold", crate::registry::HELD_SCHEMA),
    ]
}
