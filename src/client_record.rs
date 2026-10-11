//! Fixed whole-object resource budget, independent of record verification.
use crate::error::{Error, Result};

pub(crate) const PATH: &str = "/v1/account_record_object";
pub(crate) const RESOURCE: &str = "account-record-object";
// Original czkp::record::MAX_DOWNLOAD_BYTES. Client-only builds intentionally
// do not import proof owners; the server checks the maintained owner constant.
pub(crate) const MAXIMUM: usize = 64 * 1024 * 1024;

pub(super) fn expected_length(length: usize) -> Result<()> {
    if !(1..=MAXIMUM).contains(&length) {
        return Err(Error::Invalid);
    }
    Ok(())
}

#[cfg(any(feature = "client-http", feature = "client-browser"))]
pub(super) fn content_length(value: Option<&str>, expected: usize) -> Result<()> {
    if let Some(value) = value {
        if value.parse::<u64>().map_err(Error::Reconcile.redact())? != expected as u64 {
            return Err(Error::Reconcile);
        }
    }
    Ok(())
}
