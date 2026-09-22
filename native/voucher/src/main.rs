use std::io::{self, Read};

use cmsg::{member_id_for_root, verify_device_authorization, DeviceAuthorization};
use cvch::{member_binding, receipt_id, verify, Voucher};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

const MAX_INPUT: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: String,
    voucher: Option<VoucherWire>,
    community_id: Option<String>,
    sponsor_public_key: Option<String>,
    member_id: Option<String>,
    now_secs: Option<u64>,
    authorization: Option<DeviceAuthorization>,
    chat_public_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VoucherWire {
    id: String,
    valid_until: u64,
    signature: String,
}

#[derive(Serialize)]
struct Success {
    ok: bool,
    receipt_id: String,
    member_binding: String,
    valid_until: u64,
}

fn reject() -> String {
    // Deliberately uniform: no sponsor, voucher or parse detail is returned.
    r#"{"ok":false}"#.to_owned()
}

fn run(input: &[u8]) -> Option<String> {
    let request: Request = serde_json::from_slice(input).ok()?;
    match request.op.as_str() {
        "verify" => {
            let community_id = request.community_id.as_deref()?;
            let sponsor_public_key = request.sponsor_public_key.as_deref()?;
            let member_id = request.member_id.as_deref()?;
            let now_secs = request.now_secs?;
            if community_id.is_empty() || community_id.len() > 256 || !community_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte)) || now_secs > 9_007_199_254_740_991 {
                return None;
            }
            let sponsor = BASE64URL_NOPAD.decode(sponsor_public_key.as_bytes()).ok()?;
            let sponsor: [u8; 32] = sponsor.try_into().ok()?;
            let sponsor = VerifyingKey::from_bytes(&sponsor).ok()?;
            if sponsor.is_weak() || BASE64URL_NOPAD.encode(sponsor.as_bytes()) != sponsor_public_key {
                return None;
            }
            let member = BASE64URL_NOPAD.decode(member_id.as_bytes()).ok()?;
            if member.len() != 32 || BASE64URL_NOPAD.encode(&member) != member_id {
                return None;
            }
            let wire = request.voucher?;
            let signature = BASE64URL_NOPAD.decode(wire.signature.as_bytes()).ok()?;
            if BASE64URL_NOPAD.encode(&signature) != wire.signature {
                return None;
            }
            let voucher = Voucher { id: wire.id, valid_until: wire.valid_until, signature };
            verify(&voucher, &sponsor, community_id, now_secs).ok()?;
            let receipt = receipt_id(&voucher.id);
            let binding = member_binding(&receipt, &member);
            serde_json::to_string(&Success { ok: true, receipt_id: receipt, member_binding: binding, valid_until: voucher.valid_until }).ok()
        }
        "verify_device" => {
            let community_id = request.community_id.as_deref()?;
            let member_id = request.member_id.as_deref()?;
            let chat_public_key = request.chat_public_key.as_deref()?;
            let now_secs = request.now_secs?;
            let key = BASE64URL_NOPAD.decode(chat_public_key.as_bytes()).ok()?;
            if key.len() != 32 || BASE64URL_NOPAD.encode(&key) != chat_public_key {
                return None;
            }
            let authorization = request.authorization?;
            verify_device_authorization(&authorization, community_id, member_id, &key, now_secs).ok()?;
            // Exercise the same root-derived member calculation as the
            // authority verifier; its result is never returned to the caller.
            let root = BASE64URL_NOPAD.decode(authorization.root_public_key.as_bytes()).ok()?;
            let root: [u8; 32] = root.try_into().ok()?;
            member_id_for_root(community_id, &root).ok()?;
            Some(r#"{"ok":true}"#.to_owned())
        }
        _ => None,
    }
}

fn main() {
    let mut input = Vec::new();
    let stdin = io::stdin();
    let mut limited = stdin.lock().take((MAX_INPUT + 1) as u64);
    if limited.read_to_end(&mut input).is_err() || input.len() > MAX_INPUT {
        println!("{}", reject());
        return;
    }
    println!("{}", run(&input).unwrap_or_else(reject));
}
