//! Literal-wallet owner attachment; passport GlobalPublic stays separate.
use super::*;
use crate::auth::wallet::WalletSession;

pub(super) type WalletOwner = cgbl::Wallet<cgbl::storage::LibsqlStore, csgn::LibsqlStore>;
impl GlobalService {
    pub(crate) async fn attach_wallet(
        &mut self,
        db: &Db,
        config: &Config,
        passkeys: std::sync::Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
        now: u64,
    ) -> Result<()> {
        let Some(config) = &config.wallet else {
            return Ok(());
        };
        if config.signing_seed_file.is_empty()
            || config.publication_file.is_empty()
            || config.signer_max_seconds == 0
        {
            return Err(Error::Invalid);
        }
        let bytes = std::fs::read(&config.publication_file).map_err(Error::Unavailable.redact())?;
        if bytes.len() > cmty::cplc::MAX_DOCUMENT_BYTES {
            return Err(Error::Invalid);
        }
        let publication = serde_json::from_slice(&bytes).map_err(Error::Invalid.redact())?;
        let store =
            csgn::LibsqlStore::new(db.community("global").map_err(Error::Invalid.redact())?);
        use csgn::Store;
        let exists = store
            .load("wallet")
            .await
            .map_err(Error::Unavailable.redact())?
            .is_some();
        let secret = csgn::SecretKey::from_seed(&mut Config::seed(&config.signing_seed_file)?);
        let day = now / 86_400 * 86_400;
        let signer = if exists {
            csgn::PersistentSigner::open(store, "wallet", secret, day).await
        } else {
            csgn::PersistentSigner::create(store, "wallet", secret, day, config.signer_max_seconds)
                .await
        }
        .map_err(Error::Unavailable.redact())?;
        self.wallet = Some(
            self.facade
                .open_wallet(signer, publication, passkeys, now)
                .await
                .map_err(Error::Refused.redact())?,
        );
        Ok(())
    }
    pub(crate) async fn wallet_certificate(
        &mut self,
        session: &WalletSession,
        clock: &dyn crate::service::Clock,
    ) -> Result<cgbl::WalletPasskeyCertificate> {
        self.facade
            .wallet_passkey_certificate(
                self.wallet.as_mut().ok_or(Error::Forbidden)?,
                session.member()?,
                session.expires(),
                &|| clock.now(),
            )
            .await
            .map_err(Error::Refused.redact())
    }
    pub(crate) async fn wallet_devices(
        &mut self,
        session: &WalletSession,
        device: Option<[u8; 32]>,
        clock: &dyn crate::service::Clock,
    ) -> Result<cgbl::WalletDeviceObservation> {
        let wallet = self.wallet.as_mut().ok_or(Error::Forbidden)?;
        match device {
            Some(device) => self
                .facade
                .authorize_wallet_device(
                    wallet,
                    session.member()?,
                    device,
                    session.expires(),
                    &|| clock.now(),
                )
                .await
                .map_err(Error::Reconcile.redact()),
            None => self
                .facade
                .wallet_devices(wallet, session.member()?, session.expires(), &|| {
                    clock.now()
                })
                .await
                .map_err(Error::Refused.redact()),
        }
    }
    pub(crate) async fn wallet_mutation(&mut self) -> Result<Option<cgbl::WalletMutation>> {
        match self.wallet.as_mut() {
            Some(wallet) => self
                .facade
                .wallet_mutation(wallet)
                .await
                .map(Some)
                .map_err(Error::Unavailable.redact()),
            None => Ok(None),
        }
    }
    pub(crate) async fn signal_wallet_mutation(
        &mut self,
        session: &WalletSession,
        mutation: &cgbl::WalletMutation,
        clock: &dyn crate::service::Clock,
    ) -> Result<()> {
        let Some(wallet) = self.wallet.as_mut() else {
            return Ok(());
        };
        self.facade
            .signal_wallet_key_mutation(
                wallet,
                session.member()?,
                mutation,
                session.expires(),
                &|| clock.now(),
            )
            .await
            .map_err(Error::Reconcile.redact())
    }
    pub(crate) async fn publish_wallet(&mut self, now: u64) -> Result<()> {
        if let Some(wallet) = &mut self.wallet {
            wallet
                .trust_feed(now)
                .await
                .map_err(Error::Reconcile.redact())?;
        }
        Ok(())
    }
}
