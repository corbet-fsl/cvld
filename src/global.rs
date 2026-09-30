use crate::{
    api::*,
    config::Config,
    error::{Error, Result},
};
use cglb::Global;
use crlt::{Db, Migration};
pub type Facade =
    Global<cglb::storage::LibsqlStore, csgn::LibsqlStore, cpsd::storage::libsql::LibsqlStore>;
pub struct GlobalService {
    pub facade: Facade,
    pub public: GlobalPublic,
    pub changes: tokio::sync::watch::Sender<std::sync::Arc<GlobalPublic>>,
    pub publication_seconds: u64,
    #[cfg(feature = "development-gate")]
    pub development_expiry: u64,
}
impl GlobalService {
    pub async fn open(db: &Db, config: &Config, now: u64) -> Result<Self> {
        use csgn::Store;
        db.migrate(&[
            Migration::new(1, "global", cglb::storage::SCHEMA),
            Migration::new(2, "signing", csgn::SCHEMA),
            Migration::new(3, "passkeys", cpky::LIBSQL_SCHEMA),
            Migration::new(4, "service", crate::identity::SCHEMA),
            Migration::new(5, "passport-challenges", cpsd::storage::libsql::SCHEMA),
            Migration::new(
                6,
                "passport-issuance",
                cpsd::storage::libsql::ISSUANCE_SCHEMA,
            ),
            Migration::new(
                7,
                "passport-owners",
                cpsd::storage::libsql::ISSUANCE_UNIQUENESS_SCHEMA,
            ),
        ])
        .await
        .map_err(|_| Error::Unavailable)?;
        crate::identity::bind(db, "global", "global").await?;
        let store = csgn::LibsqlStore::new(db.community("global").map_err(|_| Error::Invalid)?);
        let exists = store
            .load("cglb:global")
            .await
            .map_err(|_| Error::Unavailable)?
            .is_some();
        let secret = csgn::SecretKey::from_seed(&mut Config::seed(&config.signing_seed_file)?);
        let signer = if exists {
            csgn::PersistentSigner::open(store, "cglb:global", secret, now).await
        } else {
            csgn::PersistentSigner::create(
                store,
                "cglb:global",
                secret,
                now / 86_400 * 86_400,
                config.signer_max_seconds,
            )
            .await
        }
        .map_err(|_| Error::Unavailable)?;
        let issuer = cpsd::IssuerKey::from_secret_bytes(&Config::secret(&config.issuer_key_file)?)
            .map_err(|_| Error::Invalid)?;
        #[cfg(feature = "development-gate")]
        let mode = if config.development {
            cglb::Mode::Development
        } else {
            cglb::Mode::Production
        };
        #[cfg(not(feature = "development-gate"))]
        let mode = {
            if config.development {
                return Err(Error::Forbidden);
            }
            cglb::Mode::Production
        };
        let mut facade = Global::open(
            cglb::storage::LibsqlStore::new(db, "global").map_err(|_| Error::Invalid)?,
            cpsd::storage::libsql::LibsqlStore::new(
                db,
                cpsd::CommunityId::new("global").map_err(|_| Error::Invalid)?,
                config.pending_capacity,
            )
            .map_err(|_| Error::Unavailable)?,
            issuer,
            signer,
            cglb::FingerprintKey::from_bytes(&mut Config::seed(&config.uniqueness_key_file)?),
            mode,
            cglb::Limits {
                challenge_ttl: 60,
                pending_capacity: config
                    .pending_capacity
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            },
        )
        .await
        .map_err(|_| Error::Unavailable)?;
        let policy = std::fs::read(&config.policy_file).map_err(|_| Error::Unavailable)?;
        let authority = csgn::KeyRing::from_cbor(
            &std::fs::read(&config.policy_authority_file).map_err(|_| Error::Unavailable)?,
        )
        .map_err(|_| Error::Invalid)?;
        facade
            .install_policy(&policy, &authority, now)
            .await
            .map_err(|_| Error::Refused)?;
        let status = facade
            .signed_status(now, now + config.publication_seconds)
            .await
            .map_err(|_| Error::Refused)?;
        #[cfg(feature = "development-gate")]
        let development_expiry = {
            let ring = facade.key_ring().map_err(|_| Error::Unavailable)?;
            let verified = ring
                .verify(&status, csgn::Kind::SettingsSnapshot, now)
                .map_err(|_| Error::Unavailable)?;
            let view: cglb::Status =
                serde_json::from_slice(verified.payload()).map_err(|_| Error::Unavailable)?;
            view.shared_expiry
        };
        let public = GlobalPublic {
            key_ring: facade.key_ring().map_err(|_| Error::Unavailable)?.to_cbor(),
            issuer: facade.issuer_public_key().to_bytes(),
            status,
        };
        let (changes, _) = tokio::sync::watch::channel(std::sync::Arc::new(public.clone()));
        Ok(Self {
            facade,
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
            .map_err(|_| Error::Refused)?;
        self.public.key_ring = self
            .facade
            .key_ring()
            .map_err(|_| Error::Unavailable)?
            .to_cbor();
        self.changes
            .send_replace(std::sync::Arc::new(self.public.clone()));
        Ok(())
    }
}
