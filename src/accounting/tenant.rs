//! Accounting for communities created through the hub: everything platform-wide
//! (circuits, proof artifacts, verifier keys, limits, execution) comes from the
//! template; everything community-specific is derived here, once, for one
//! incarnation, and kept in a private directory so a restart reopens the same
//! inputs. A community's account owners never share a key with another
//! community or with an earlier incarnation of the same address. The one
//! exception is the certificate issuer: the extension artifacts pin its public
//! key, so it is platform-wide like the circuits, and every certificate it
//! signs names its community.
use super::config::{AccountConfig, bounded};
use crate::error::{Error, Result};
use cblc::accounting::AccountStatement;
use cmty::cplc::crbk;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

const DAY: u64 = 86_400;
/// RSA modulus of the daily outcome-deposit key.
const SETTLEMENT_BITS: u32 = 3072;
/// Largest activation statement or proof a creator may upload.
const MAX_STATEMENT: usize = 64 * 1024;
const MAX_PROOF: usize = 4 * 1024 * 1024;

/// What a creator's device needs to prove this community's accounting genesis: the
/// account policy window and the extension policy the hub will run with. Public.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingTerms {
    /// The standing and voucher values of the community's rulebook (every key
    /// `czkp::standing::RULEBOOK_KEYS` names). A device derives the parameters from
    /// them with the same function the hub used for the extension policy's digest.
    pub standing: serde_json::Map<String, serde_json::Value>,
    /// The hub's clock when it named these terms; the proof is dated by it, so a
    /// device with a skewed clock still proves for the right window.
    pub observed_at: u64,
    /// The ledger policy (`account` section included), with this day's window.
    pub ledger_policy: serde_json::Value,
    /// The extension policy, carrying the published standing digest.
    pub extension_policy: serde_json::Value,
}

/// The genesis proof a creator's device made for exactly this community.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub statement: serde_json::Value,
    pub proof: Vec<u8>,
    /// The one-time owner this creation's proof must bind: the hub derives it from
    /// the address and the creation token's message (`czkp::activation_owner`), never
    /// from anything the uploader says.
    #[serde(default)]
    pub owner: [u8; 32],
}

fn day_start(now: u64) -> u64 {
    now - now % DAY
}

fn read_json(path: &str) -> Result<serde_json::Value> {
    serde_json::from_slice(&bounded(path, 1024 * 1024)?).map_err(Error::Invalid.redact())
}

fn number(value: &serde_json::Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or(Error::Invalid)
}

/// The directory name of one incarnation, from its derived founding seed, never
/// from the seed itself.
fn directory_name(seed: &[u8; 32]) -> String {
    let digest = Sha256::digest([b"cvld.account.tenant.v1\0".as_slice(), seed].concat());
    crate::hub::hex(&digest[..16])
}

fn derive(seed: &[u8; 32], label: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b"cvld.account.tenant.v1"), seed)
        .expand(label, &mut out)
        .map_err(|_| Error::Unavailable)?;
    Ok(out)
}

/// Create the file with owner-only access, or leave an existing identical or
/// earlier file alone: a key, once made, is never replaced.
fn keep(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let staging = path.with_extension("part");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(&staging)
        .map_err(Error::Unavailable.redact())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(Error::Unavailable.redact())?;
    fs::rename(&staging, path).map_err(Error::Unavailable.redact())
}

impl AccountConfig {
    /// Whether this configuration is a template for hub-created communities.
    pub fn is_template(&self) -> bool {
        self.tenants_dir.is_some()
    }

    /// The terms for a community created today (a device proves against them).
    pub fn terms(&self, now: u64, rulebook: &crbk::Rulebook) -> Result<AccountingTerms> {
        self.terms_for(day_start(now), now, rulebook)
    }

    fn terms_for(&self, from: u64, now: u64, rulebook: &crbk::Rulebook) -> Result<AccountingTerms> {
        let mut ledger = read_json(&self.ledger_policy_file)?;
        let account = ledger.get_mut("account").ok_or(Error::Invalid)?;
        let span = number(account, "policyValidUntil")?
            .checked_sub(number(account, "policyValidFrom")?)
            .filter(|span| *span >= DAY)
            .ok_or(Error::Invalid)?;
        account["policyValidFrom"] = from.into();
        account["policyValidUntil"] = from.checked_add(span).ok_or(Error::Invalid)?.into();
        // The standing policy digest is never taken from a file: it is the digest of
        // the parameters the community's own rulebook resolves to.
        let values = rulebook
            .resolve(&Default::default())
            .map_err(Error::Invalid.redact())?;
        let params = crbk::standing_params(&values).map_err(Error::Invalid.redact())?;
        let digest = params.policy_digest().map_err(Error::Invalid.redact())?;
        let mut extension = read_json(&self.extension_policy_file)?;
        extension["standingPolicyDigest"] = digest.to_vec().into();
        let standing = czkp::standing::RULEBOOK_KEYS
            .iter()
            .map(|key| {
                values
                    .get(*key)
                    .map(|value| ((*key).to_owned(), value.clone()))
                    .ok_or(Error::Invalid)
            })
            .collect::<Result<_>>()?;
        Ok(AccountingTerms {
            standing,
            observed_at: now,
            ledger_policy: ledger,
            extension_policy: extension,
        })
    }

    /// Check an uploaded activation before anything is created from it: the policy
    /// window is today's or yesterday's UTC day (a device that proved across
    /// midnight is still accepted) and the policy equals the terms for that day.
    /// The ledger itself verifies the proof and that it names this community.
    pub fn check_activation(
        &self,
        activation: &Activation,
        now: u64,
        rulebook: &crbk::Rulebook,
    ) -> Result<u64> {
        if activation.proof.is_empty()
            || activation.proof.len() > MAX_PROOF
            || serde_json::to_vec(&activation.statement)
                .map_err(Error::Invalid.redact())?
                .len()
                > MAX_STATEMENT
        {
            return Err(Error::Invalid);
        }
        let statement: AccountStatement = serde_json::from_value(activation.statement.clone())
            .map_err(Error::Invalid.redact())?;
        // The proof must bind this creation's one-time value: a proof made for an
        // earlier incarnation of the name (another token) is refused here, and the
        // ledger refuses a statement for another community id.
        if activation.owner == [0; 32] || statement.owner != activation.owner {
            return Err(Error::Invalid);
        }
        let from = statement.policy.policy_valid_from;
        let today = day_start(now);
        if !from.is_multiple_of(DAY) || (from != today && from + DAY != today) {
            return Err(Error::Invalid);
        }
        let terms = self.terms_for(from, now, rulebook)?;
        let expected: cblc::accounting_ledger::AccountLedgerPolicy =
            serde_json::from_value(terms.ledger_policy).map_err(Error::Invalid.redact())?;
        if statement.policy != expected.account {
            return Err(Error::Invalid);
        }
        Ok(from)
    }

    /// Delete everything derived for one incarnation (a failed creation or an ended
    /// community). Best effort and idempotent.
    pub fn forget_tenant(&self, seed: &[u8; 32]) {
        if let Some(base) = &self.tenants_dir {
            let _ = fs::remove_dir_all(Path::new(base).join(directory_name(seed)));
        }
    }

    /// The configuration of one community incarnation. The derived seeds, daily
    /// settlement epoch and key, and policy files are created on first use and
    /// reused afterwards; `activation` is stored with them when given. Without a
    /// stored activation the community cannot be opened.
    pub fn for_tenant(
        &self,
        community: &str,
        seed: &[u8; 32],
        now: u64,
        rulebook: &crbk::Rulebook,
        activation: Option<(&Activation, u64)>,
    ) -> Result<AccountConfig> {
        let base = PathBuf::from(self.tenants_dir.as_deref().ok_or(Error::Invalid)?);
        if !base.is_absolute() {
            return Err(Error::Invalid);
        }
        let name = directory_name(seed);
        let dir = base.join(&name);
        fs::create_dir_all(&dir).map_err(Error::Unavailable.redact())?;
        #[cfg(unix)]
        fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(Error::Unavailable.redact())?;
        let file = |leaf: &str| dir.join(leaf);
        let text = |path: PathBuf| path.to_string_lossy().into_owned();

        let statement = file("activation-statement.json");
        let proof = file("activation-proof");
        if let Some((activation, from)) = activation {
            let terms = self.terms_for(from, now, rulebook)?;
            keep(
                &file("ledger-policy.json"),
                &serde_json::to_vec(&terms.ledger_policy).map_err(Error::Invalid.redact())?,
            )?;
            keep(
                &file("extension-policy.json"),
                &serde_json::to_vec(&terms.extension_policy).map_err(Error::Invalid.redact())?,
            )?;
            keep(
                &statement,
                &serde_json::to_vec(&activation.statement).map_err(Error::Invalid.redact())?,
            )?;
            keep(&proof, &activation.proof)?;
        }
        if !(file("ledger-policy.json").exists() && statement.exists() && proof.exists()) {
            return Err(Error::Invalid);
        }
        keep(&file("operator-seed"), &derive(seed, b"operator")?)?;
        keep(&file("rooms.json"), b"[]")?;

        // One outcome-deposit epoch per UTC day, each with its own private key
        // that is made once and never recreated (a lost key is not replaced).
        let day = now / DAY;
        let epoch_file = file(&format!("epoch-{day}.json"));
        let key_file = file(&format!("outcome-key-{day}.der"));
        if !(epoch_file.exists() && key_file.exists()) {
            let rsa = openssl::rsa::Rsa::generate(SETTLEMENT_BITS)
                .map_err(Error::Unavailable.redact())?;
            let private = rsa
                .private_key_to_der()
                .map_err(Error::Unavailable.redact())?;
            let public = rsa
                .public_key_to_der()
                .map_err(Error::Unavailable.redact())?;
            // The key first: an epoch file never exists without its key.
            keep(&key_file, &private)?;
            keep(
                &epoch_file,
                &serde_json::to_vec(&serde_json::json!({
                    "purpose": "outcome-deposit-v1",
                    "community": community,
                    "epoch": day,
                    "valid_from": day * DAY * 1000,
                    "valid_until": (day + 1) * DAY * 1000,
                    "public_key_der": public,
                }))
                .map_err(Error::Invalid.redact())?,
            )?;
        }

        let mut config = self.clone();
        config.tenants_dir = None;
        config.ledger_policy_file = text(file("ledger-policy.json"));
        config.extension_policy_file = text(file("extension-policy.json"));
        config.operator_seed_file = text(file("operator-seed"));
        // The certificate issuer stays the template's: its public key is pinned by
        // the platform's extension artifacts, so a derived key would never verify.
        config.activation_statement_file = text(statement);
        config.activation_proof_file = text(proof);
        config.settlement.epoch_file = text(epoch_file);
        config.settlement.private_key_file = text(key_file);
        config.settlement.room_epochs_file = text(file("rooms.json"));
        config.settlement.incarnation = name;
        Ok(config)
    }
}

#[cfg(test)]
mod tests;
