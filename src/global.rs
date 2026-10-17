use crate::{
    api::*,
    config::Config,
    error::{Error, Result},
};
use cgbl::Global;
mod wallet;
use crlt::Db;
#[cfg(test)]
mod tests;
pub type Facade =
    Global<cgbl::storage::LibsqlStore, csgn::LibsqlStore, cpsd::storage::libsql::LibsqlStore>;
pub struct GlobalService {
    pub(crate) wallet: Option<wallet::WalletOwner>,
    pub facade: Facade,
    pub contacts: Option<crate::contact_gates::Contacts>,
    pub contact_ceremony_seconds: Option<u64>,
    pub public: GlobalPublic,
    pub changes: tokio::sync::watch::Sender<std::sync::Arc<GlobalPublic>>,
    pub publication_seconds: u64,
    #[cfg(feature = "development-gate")]
    pub development_expiry: u64,
}
impl GlobalService {
    #[cfg(test)]
    pub async fn open(
        db: &Db,
        config: &Config,
        now: u64,
        clock: std::sync::Arc<dyn crate::service::Clock>,
    ) -> Result<Self> {
        Self::open_with_transport(db, config, now, clock, None).await
    }
    pub async fn open_with_transport(
        db: &Db,
        config: &Config,
        now: u64,
        clock: std::sync::Arc<dyn crate::service::Clock>,
        transport: Option<crate::contact_gates::transport::AnyTransport>,
    ) -> Result<Self> {
        use csgn::Store;
        db.migrate(&crate::service::global_migrations())
            .await
            .map_err(Error::Unavailable.redact())?;
        crate::identity::bind(db, "global", "global").await?;
        let store =
            csgn::LibsqlStore::new(db.community("global").map_err(Error::Invalid.redact())?);
        let exists = store
            .load("cgbl:global")
            .await
            .map_err(Error::Unavailable.redact())?
            .is_some();
        let secret = csgn::SecretKey::from_seed(&mut Config::seed(&config.signing_seed_file)?);
        // cgbl signs and rotates at UTC day boundaries. Resume in that same
        // time domain; csgn still rejects a day before its persisted clock.
        let signing_day = now / 86_400 * 86_400;
        let signer = if exists {
            csgn::PersistentSigner::open(store, "cgbl:global", secret, signing_day).await
        } else {
            csgn::PersistentSigner::create(
                store,
                "cgbl:global",
                secret,
                signing_day,
                config.signer_max_seconds,
            )
            .await
        }
        .map_err(Error::Unavailable.redact())?;
        let issuer = cpsd::IssuerKey::from_secret_bytes(&Config::secret(&config.issuer_key_file)?)
            .map_err(Error::Invalid.redact())?;
        #[cfg(feature = "development-gate")]
        let mode = if config.development {
            cgbl::Mode::Development
        } else {
            cgbl::Mode::Production
        };
        #[cfg(not(feature = "development-gate"))]
        let mode = {
            if config.development {
                return Err(Error::Forbidden);
            }
            cgbl::Mode::Production
        };
        let mut facade = Global::open(
            cgbl::storage::LibsqlStore::new(db, "global").map_err(Error::Invalid.redact())?,
            cpsd::storage::libsql::LibsqlStore::new(
                db,
                cpsd::CommunityId::new("global").map_err(Error::Invalid.redact())?,
                config.pending_capacity,
            )
            .map_err(Error::Unavailable.redact())?,
            issuer,
            signer,
            cgbl::FingerprintKey::from_bytes(&mut Config::seed(&config.uniqueness_key_file)?),
            mode,
            cgbl::Limits {
                challenge_ttl: 60,
                pending_capacity: config
                    .pending_capacity
                    .try_into()
                    .map_err(Error::Invalid.redact())?,
            },
        )
        .await
        .map_err(Error::Unavailable.redact())?;
        if let Some(wallet) = &config.wallet
            && let Some(file) = &wallet.stamp_key_file
        {
            let key = cpsd::StampIssuerKey::from_secret_bytes(&Config::secret(file)?)
                .map_err(Error::Invalid.redact())?;
            let defaults = cgbl::StampRate::default();
            facade
                .attach_stamps(
                    key,
                    cgbl::StampRate {
                        limit: wallet.stamp_limit.unwrap_or(defaults.limit),
                        period_seconds: wallet
                            .stamp_period_seconds
                            .unwrap_or(defaults.period_seconds),
                        replay_seconds: wallet
                            .stamp_replay_seconds
                            .unwrap_or(defaults.replay_seconds),
                    },
                )
                .map_err(Error::Invalid.redact())?;
        }
        let policy = std::fs::read(&config.policy_file).map_err(Error::Unavailable.redact())?;
        let authority = csgn::KeyRing::from_cbor(
            &std::fs::read(&config.policy_authority_file).map_err(Error::Unavailable.redact())?,
        )
        .map_err(Error::Invalid.redact())?;
        facade
            .install_policy(&policy, &authority, now)
            .await
            .map_err(Error::Refused.redact())?;
        let status = facade
            .signed_status(now, now + config.publication_seconds)
            .await
            .map_err(Error::Refused.redact())?;
        #[cfg(feature = "development-gate")]
        let development_expiry = {
            let ring = facade.key_ring().map_err(Error::Unavailable.redact())?;
            let verified = ring
                .verify(&status, csgn::Kind::SettingsSnapshot, now)
                .map_err(Error::Unavailable.redact())?;
            let view: cgbl::Status =
                serde_json::from_slice(verified.payload()).map_err(Error::Unavailable.redact())?;
            view.shared_expiry
        };
        let public = GlobalPublic {
            key_ring: facade
                .key_ring()
                .map_err(Error::Unavailable.redact())?
                .to_cbor(),
            issuer: facade.issuer_public_key().to_bytes(),
            status,
        };
        let (changes, _) = tokio::sync::watch::channel(std::sync::Arc::new(public.clone()));
        let contacts = match (&config.contacts, transport) {
            (Some(contacts), Some(transport)) => Some(
                crate::contact_gates::Contacts::with_transport(
                    db, "global", contacts, clock, transport,
                )
                .await
                .map_err(Error::Invalid.redact())?,
            ),
            (Some(contacts), None) => Some(
                crate::contact_gates::Contacts::configured(db, "global", contacts, clock)
                    .await
                    .map_err(Error::Invalid.redact())?,
            ),
            (None, Some(_)) => return Err(Error::Invalid),
            (None, None) => None,
        };
        Ok(Self {
            wallet: None,
            facade,
            contacts,
            contact_ceremony_seconds: config
                .contacts
                .as_ref()
                .map(|contacts| contacts.ceremony_seconds),
            public,
            changes,
            publication_seconds: config.publication_seconds,
            #[cfg(feature = "development-gate")]
            development_expiry,
        })
    }
    pub async fn refresh(&mut self, now: u64) -> Result<()> {
        self.public.status = self
            .facade
            .signed_status(now, now + self.publication_seconds)
            .await
            .map_err(Error::Refused.redact())?;
        self.public.key_ring = self
            .facade
            .key_ring()
            .map_err(Error::Unavailable.redact())?
            .to_cbor();
        self.changes
            .send_replace(std::sync::Arc::new(self.public.clone()));
        Ok(())
    }
}
