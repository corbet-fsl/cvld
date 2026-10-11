//! Provisioned maintained RSA and original codecs only. No current Policy,
//! native proof or usable host authority is fabricated by these loader tests.
use super::*;
use openssl::rsa::Rsa;
use serde_json::{Value, json};
use std::path::Path;

fn write(path: &Path, name: &str, bytes: &[u8]) -> String {
    let target = path.join(name);
    std::fs::write(&target, bytes).unwrap();
    target.to_str().unwrap().into()
}
fn target() -> Target {
    Target {
        policy_epoch: 7,
        period_seconds: 86_400,
        quota: 4,
    }
}
fn files(path: &Path) -> SettlementFiles {
    let rsa = Rsa::generate(3072).unwrap();
    let private = zeroize::Zeroizing::new(rsa.private_key_to_der().unwrap());
    let epoch = json!({
        "purpose":"outcome-deposit-v1","community":"alpha","epoch":1,
        "valid_from":86_400_000,"valid_until":172_800_000,
        "public_key_der":rsa.public_key_to_der().unwrap()
    });
    SettlementFiles {
        quota_key: "outcomes/allowance".into(),
        epoch_file: write(path, "epoch.json", &serde_json::to_vec(&epoch).unwrap()),
        private_key_file: write(path, "outcome-key.der", &private),
        room_epochs_file: write(path, "rooms.json", b"[]"),
        incarnation: "original-host-fixture".into(),
        pending_capacity: 8,
        issuance_members_capacity: 8,
    }
}

#[test]
fn provisioned_owner_matches_original_epoch_and_independent_daily_target() {
    let dir = tempfile::tempdir().unwrap();
    let files = files(dir.path());
    let prepared = files.prepare("alpha", target()).unwrap();
    assert!(prepared.issuer.epoch() == &prepared.config.epoch);
    assert_eq!(prepared.config.policy_epoch, 7);
    assert_eq!(
        (prepared.config.period_seconds, prepared.config.quota),
        (86_400, 4)
    );
    assert!(prepared.config.room_epochs.is_empty());
    assert_eq!(prepared.quota_key, "outcomes/allowance");
    assert_eq!(prepared.incarnation, "original-host-fixture");
}

#[test]
fn missing_settings_or_original_key_mismatch_cannot_choose_fallback_authority() {
    let dir = tempfile::tempdir().unwrap();
    let mut files = files(dir.path());
    assert!(matches!(
        files.prepare("another", target()),
        Err(Error::Invalid)
    ));
    let mut non_daily = target();
    non_daily.period_seconds = 100;
    assert!(matches!(
        files.prepare("alpha", non_daily),
        Err(Error::Invalid)
    ));
    let mut no_quota = target();
    no_quota.quota = 0;
    assert!(matches!(
        files.prepare("alpha", no_quota),
        Err(Error::Invalid)
    ));
    files.quota_key.clear();
    assert!(matches!(
        files.prepare("alpha", target()),
        Err(Error::Invalid)
    ));
    files.quota_key = "outcomes/allowance".into();
    let other = zeroize::Zeroizing::new(Rsa::generate(3072).unwrap().private_key_to_der().unwrap());
    std::fs::write(&files.private_key_file, &other).unwrap();
    assert!(matches!(
        files.prepare("alpha", target()),
        Err(Error::Invalid)
    ));
    std::fs::write(&files.private_key_file, vec![7u8; 16_385]).unwrap();
    assert!(matches!(
        files.prepare("alpha", target()),
        Err(Error::Invalid)
    ));
    std::fs::remove_file(&files.private_key_file).unwrap();
    assert!(matches!(
        files.prepare("alpha", target()),
        Err(Error::Unavailable)
    ));
}

#[test]
fn same_room_key_and_missing_or_oversized_inventory_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let files = files(dir.path());
    let mut room: Value =
        serde_json::from_slice(&std::fs::read(&files.epoch_file).unwrap()).unwrap();
    room.as_object_mut().unwrap().remove("purpose");
    std::fs::write(
        &files.room_epochs_file,
        serde_json::to_vec(&vec![room]).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        files.prepare("alpha", target()),
        Err(Error::Invalid)
    ));
    std::fs::write(&files.room_epochs_file, vec![b' '; 256 * 1024 + 1]).unwrap();
    assert!(matches!(
        files.prepare("alpha", target()),
        Err(Error::Invalid)
    ));
    std::fs::remove_file(&files.room_epochs_file).unwrap();
    assert!(matches!(
        files.prepare("alpha", target()),
        Err(Error::Unavailable)
    ));
}

#[test]
fn public_files_cannot_inject_current_policy_fields_or_weaken_resource_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let mut files = files(dir.path());
    let original = std::fs::read(&files.epoch_file).unwrap();
    let mut epoch: Value = serde_json::from_slice(&original).unwrap();
    epoch["quota"] = 1024.into();
    std::fs::write(&files.epoch_file, serde_json::to_vec(&epoch).unwrap()).unwrap();
    assert!(matches!(
        files.prepare("alpha", target()),
        Err(Error::Invalid)
    ));
    std::fs::write(&files.epoch_file, original).unwrap();
    files.pending_capacity = 0;
    assert!(matches!(
        files.prepare("alpha", target()),
        Err(Error::Invalid)
    ));
    files.pending_capacity = 8;
    files.issuance_members_capacity = (1 << 20) + 1;
    assert!(matches!(
        files.prepare("alpha", target()),
        Err(Error::Invalid)
    ));
}
