//! A fixed anonymous common resource; there is no recipient lookup.
use super::*;
impl Door {
    pub(crate) async fn account_record(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<AccountRecordResource> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .current_account_record()
            .await?;
        Ok(AccountRecordResource {
            path: crate::client::record::PATH.into(),
            media_type: "application/octet-stream".into(),
        })
    }
    pub(crate) async fn account_record_bytes(&self, ctx: Context) -> Result<axum::body::Bytes> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .current_account_record()
            .await
    }
}
