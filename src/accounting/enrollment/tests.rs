use super::*;
use serde_json::json;

#[test]
fn registry_inherits_exact_native_identity_and_explicit_limits() {
    let limits: EnrollmentLimits = serde_json::from_value(json!({
        "max_members":19,
        "max_retained_slots":7,
        "max_publication_bytes":32768,
    }))
    .unwrap();
    let operator = ed25519_dalek_v2::SigningKey::from_bytes(&[47; 32])
        .verifying_key()
        .to_bytes();
    let digest = "A".repeat(43);
    let config = limits
        .configuration("alpha", &digest, operator, 120)
        .unwrap();
    assert_eq!(config.community_id, "alpha");
    assert_eq!(config.policy_digest, digest);
    assert_eq!(config.operator_public_key, operator);
    assert_eq!(config.checkpoint_period_seconds, 120);
    assert_eq!(config.max_members, 19);
    assert_eq!(config.max_retained_slots, 7);
    assert_eq!(config.max_publication_bytes, 32768);

    // Capacity-only input cannot override any independently configured identity.
    for name in [
        "community_id",
        "policy_digest",
        "operator_public_key",
        "checkpoint_period_seconds",
    ] {
        let mut extra = serde_json::to_value(&limits).unwrap();
        extra[name] = json!("caller-selected");
        assert!(serde_json::from_value::<EnrollmentLimits>(extra).is_err());
    }
    for name in ["max_members", "max_retained_slots", "max_publication_bytes"] {
        let mut missing = serde_json::to_value(&limits).unwrap();
        missing.as_object_mut().unwrap().remove(name);
        assert!(serde_json::from_value::<EnrollmentLimits>(missing).is_err());
        let mut zero = serde_json::to_value(&limits).unwrap();
        zero[name] = json!(0);
        let zero: EnrollmentLimits = serde_json::from_value(zero).unwrap();
        assert!(matches!(
            zero.configuration("alpha", &digest, operator, 120),
            Err(Error::Invalid)
        ));
    }
    assert!(matches!(
        limits.configuration("alpha", &digest, operator, 0),
        Err(Error::Invalid)
    ));
}
