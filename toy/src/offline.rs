//! A small cfrm stand-in: all verification takes only already-pulled bytes.
use crate::process::Result;
use cmty::cplc::{self, SnapshotKind};
use cvld::api::TrustFeed;
use serde_json::Value;
use std::collections::BTreeMap;

pub struct Verifier {
    pub community: String,
    pub ring: csgn::KeyRing,
    revision: u64,
    epoch: u64,
    floors: BTreeMap<String, u64>,
    schema: u32,
    revocations: cplc::Revocations,
    fresh_until: u64,
}
impl Verifier {
    pub fn new(community: &str, ring: csgn::KeyRing) -> Self {
        Self {
            community: community.into(),
            ring,
            revision: 0,
            epoch: 0,
            floors: BTreeMap::new(),
            schema: 0,
            revocations: cplc::Revocations::default(),
            fresh_until: 0,
        }
    }
    pub fn update(&mut self, feed: &TrustFeed, now: u64) -> Result<Value> {
        if feed.key_ring != self.ring.to_cbor() {
            return Err("untrusted ring substitution".into());
        }
        let signed = self
            .ring
            .verify(&feed.manifest, csgn::Kind::SettingsSnapshot, now)
            .map_err(|_| "invalid manifest")?;
        let manifest: cplc::TrustManifest =
            serde_json::from_slice(signed.payload()).map_err(|_| "manifest payload")?;
        if manifest.community != self.community
            || manifest.revision != feed.revision
            || manifest.policy_epoch != feed.policy_epoch
            || manifest.key_ring != feed.key_ring
            || feed.revision < self.revision
            || feed.policy_epoch < self.epoch
        {
            return Err("scope or trust rollback".into());
        }
        let mut floors = self.floors.clone();
        let mut settings = Value::Null;
        let mut revocations = cplc::Revocations::default();
        let mut fresh_until = signed.valid_until();
        for (name, kind, bytes) in [
            ("settings", SnapshotKind::Settings, &feed.settings),
            ("schema", SnapshotKind::Schema, &feed.schema),
            (
                "schema_versions",
                SnapshotKind::SchemaVersions,
                &feed.schema_versions,
            ),
            ("communities", SnapshotKind::Communities, &feed.communities),
            (
                "revocations",
                SnapshotKind::RevocationList,
                &feed.revocations,
            ),
        ] {
            let document: cplc::Snapshot<Value> = cplc::verify_snapshot(
                &self.ring,
                bytes,
                cplc::SnapshotExpectation {
                    community: &self.community,
                    kind,
                    minimum_revision: *floors.get(name).unwrap_or(&1),
                    policy_epoch: feed.policy_epoch,
                    now,
                },
            )
            .map_err(|_| "invalid snapshot")?;
            let cose_kind = kind.signing_kind();
            // cplc above verifies the exact protected kind; retain expiry for offline use.
            fresh_until = fresh_until.min(
                self.ring
                    .verify(bytes, cose_kind, now)
                    .map_err(|_| "snapshot expiry")?
                    .valid_until(),
            );
            floors.insert(name.into(), document.revision);
            match name {
                "settings" => settings = document.content,
                "schema" if document.content["version"] != manifest.schema_version => {
                    return Err("schema manifest mismatch".into());
                }
                "schema_versions" => {
                    let archive: cplc::SchemaVersions = serde_json::from_value(document.content)
                        .map_err(|_| "schema archive purpose or shape")?;
                    if archive.current != manifest.schema_version
                        || !archive
                            .versions
                            .iter()
                            .any(|version| version.schema.version == archive.current)
                    {
                        return Err("schema archive disagrees with manifest".into());
                    }
                }
                "revocations" => {
                    revocations =
                        serde_json::from_value(document.content).map_err(|_| "revocation list")?
                }
                _ => (),
            }
        }
        self.floors = floors;
        self.revision = feed.revision;
        self.epoch = feed.policy_epoch;
        self.schema = manifest.schema_version;
        self.revocations = revocations;
        self.fresh_until = fresh_until;
        Ok(settings)
    }
    pub fn credential(&self, bytes: &[u8], now: u64) -> Result<cplc::Credential> {
        if now >= self.fresh_until {
            return Err("expired trust feed".into());
        }
        let verified = self
            .ring
            .verify(bytes, csgn::Kind::Credential, now)
            .map_err(|_| "invalid credential")?;
        let credential: cplc::Credential =
            serde_json::from_slice(verified.payload()).map_err(|_| "credential payload")?;
        if credential.community != self.community
            || credential.policy_epoch != self.epoch
            || credential.schema_version != self.schema
            || self.revocations.members.contains(&credential.member)
            || credential.devices.is_empty()
            || credential
                .devices
                .iter()
                .any(|key| self.revocations.devices.contains(key))
        {
            return Err("credential not currently admitted".into());
        }
        Ok(credential)
    }
}
