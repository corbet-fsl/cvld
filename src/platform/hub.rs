//! Multi-tenant hosting inside the platform process: the registry-backed hub
//! replaces explicit community links. Nothing here is reachable from a request.
use super::*;
use crate::{
    address::Reserved,
    creation_token::{Issuer, Limits},
    hosts::{CloudflareProvisioner, HostProvisioner, NoopProvisioner},
    hub::{Factory, Hub, HubParts},
    service::{Clock, NativeConstruction, RootBoardPurpose},
};
use cmty::cplc::crbk;
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HubFiles {
    /// A complete community configuration used as the template; its `community`,
    /// `listen` and signing seed are replaced for every created community.
    template_config: String,
    /// Platform charter master secret (at least 32 bytes).
    master_secret_file: String,
    /// Private RSA key (DER) for creation tokens; used for nothing else.
    token_issuer_file: String,
    /// JSON array of reserved addresses maintained by Root.
    #[serde(default)]
    reserved_file: Option<String>,
    /// Lifetime of an unclaimed community shell.
    shell_seconds: u64,
    /// Raw 32-byte public X25519 key of the root hold key (a PUBLIC key). Without
    /// it a legal hold is refused; the secret half stays offline with Root.
    #[serde(default)]
    hold_public_key_file: Option<String>,
    #[serde(default)]
    per_week: Option<u32>,
    #[serde(default)]
    per_year: Option<u32>,
    provisioner: ProvisionerFiles,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum ProvisionerFiles {
    Noop,
    Cloudflare {
        account: String,
        zone: String,
        token_file: String,
        community_worker: String,
        vault_worker: String,
    },
}

pub(super) struct Prepared {
    template: Vec<u8>,
    master: zeroize::Zeroizing<Vec<u8>>,
    issuer: Issuer,
    reserved: Reserved,
    shell_seconds: u64,
    limits: Limits,
    hold_key: Option<[u8; 32]>,
    provisioner: Arc<dyn HostProvisioner>,
}

pub(super) fn read(files: &HubFiles) -> Result<Prepared> {
    let template = std::fs::read(&files.template_config).map_err(Error::Unavailable.redact())?;
    // The template must parse as a community configuration before any start.
    serde_json::from_slice::<CommunityConfig>(&template)
        .map_err(Error::Invalid.redact())?
        .check_account_grant(&files.template_config)?;
    let reserved: Vec<String> = match &files.reserved_file {
        Some(path) => {
            serde_json::from_slice(&std::fs::read(path).map_err(Error::Unavailable.redact())?)
                .map_err(Error::Invalid.redact())?
        }
        None => Vec::new(),
    };
    let provisioner: Arc<dyn HostProvisioner> = match &files.provisioner {
        ProvisionerFiles::Noop => Arc::new(NoopProvisioner::default()),
        ProvisionerFiles::Cloudflare {
            account,
            zone,
            token_file,
            community_worker,
            vault_worker,
        } => {
            let token = String::from_utf8(Config::secret(token_file)?.to_vec())
                .map_err(Error::Invalid.redact())?;
            Arc::new(CloudflareProvisioner::new(
                account.clone(),
                zone.clone(),
                token.trim().to_owned(),
                community_worker.clone(),
                vault_worker.clone(),
            )?)
        }
    };
    let defaults = Limits::default();
    Ok(Prepared {
        template,
        master: Config::secret(&files.master_secret_file)?,
        issuer: Issuer::from_der(&Config::secret(&files.token_issuer_file)?)?,
        reserved: Reserved::new(reserved),
        shell_seconds: files.shell_seconds,
        limits: Limits {
            per_week: files.per_week.unwrap_or(defaults.per_week),
            per_year: files.per_year.unwrap_or(defaults.per_year),
        },
        hold_key: files
            .hold_public_key_file
            .as_deref()
            .map(|path| -> Result<[u8; 32]> {
                Config::secret(path)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Invalid)
            })
            .transpose()?,
        provisioner,
    })
}

/// Opens one community door from the template for a derived founding seed.
struct TemplateFactory {
    template: Vec<u8>,
    clock: Arc<dyn Clock>,
    construction: NativeConstruction,
    purpose: OnceLock<Arc<RootBoardPurpose>>,
}

impl TemplateFactory {
    /// The template's rulebook with every platform setting defined: the values a
    /// created community starts from, hence the parameters it publishes.
    fn rulebook(&self) -> Result<crbk::Rulebook> {
        let config: CommunityConfig =
            serde_json::from_slice(&self.template).map_err(Error::Invalid.redact())?;
        let mut rulebook: crbk::Rulebook = serde_json::from_slice(
            &std::fs::read(&config.rulebook_file).map_err(Error::Unavailable.redact())?,
        )
        .map_err(Error::Invalid.redact())?;
        crbk::define_platform_settings(&mut rulebook).map_err(Error::Invalid.redact())?;
        Ok(rulebook)
    }
}

impl Factory for TemplateFactory {
    fn open<'a>(
        &'a self,
        address: &'a str,
        seed: [u8; 32],
        plan: Option<crate::config::CreationPlan>,
        activation: Option<crate::accounting::Activation>,
    ) -> crate::hosts::Boxed<'a, Result<Door>> {
        Box::pin(async move {
            let mut config: CommunityConfig =
                serde_json::from_slice(&self.template).map_err(Error::Invalid.redact())?;
            config.community = address.to_owned();
            if let Some(template) = config.accounting.take() {
                if template.is_template() {
                    let now = self.clock.now();
                    let community = address.to_owned();
                    let rulebook = self.rulebook()?;
                    // Derivation includes RSA key generation: off the async executor.
                    config.accounting = Some(
                        tokio::task::spawn_blocking(move || {
                            let checked = activation
                                .map(|activation| {
                                    template
                                        .check_activation(&activation, now, &rulebook)
                                        .map(|from| (activation, from))
                                })
                                .transpose()?;
                            template.for_tenant(
                                &community,
                                &seed,
                                now,
                                &rulebook,
                                checked
                                    .as_ref()
                                    .map(|(activation, from)| (activation, *from)),
                            )
                        })
                        .await
                        .map_err(|_| Error::Unavailable)??,
                    );
                } else {
                    config.accounting = Some(template);
                }
            }
            config.founding_seed = Some(zeroize::Zeroizing::new(seed));
            config.creation = plan;
            config.shared_database = true;
            let door = Door::community_with_construction(
                config,
                self.clock.clone(),
                self.construction.clone(),
            )
            .await?;
            if let Some(purpose) = self.purpose.get() {
                door.attach_root_board_purpose(purpose.clone()).await?;
            }
            Ok(door)
        })
    }

    fn terms(&self, now: u64) -> Result<Option<crate::accounting::AccountingTerms>> {
        let config: CommunityConfig =
            serde_json::from_slice(&self.template).map_err(Error::Invalid.redact())?;
        match config.accounting {
            Some(template) if template.is_template() => {
                template.terms(now, &self.rulebook()?).map(Some)
            }
            _ => Ok(None),
        }
    }

    fn forget(&self, seed: [u8; 32]) {
        let Ok(config) = serde_json::from_slice::<CommunityConfig>(&self.template) else {
            return;
        };
        if let Some(template) = config.accounting.filter(|template| template.is_template()) {
            template.forget_tenant(&seed);
        }
    }
}

/// Build the hub, attach it to the global door and reopen the registry's
/// communities. The global door's listener then serves the Host-routing front.
pub(super) async fn open(
    prepared: Prepared,
    global_db: (&str, Option<String>),
    base: &str,
    purpose: Option<Arc<RootBoardPurpose>>,
    clock: Arc<dyn Clock>,
    construction: &NativeConstruction,
    services: &mut [Service],
) -> Result<()> {
    let open_db = async |url: &str, token: Option<String>| -> Result<crlt::Db> {
        let mut database = crlt::Config::new(url, token.unwrap_or_default());
        database.max_connections = 2;
        crlt::Db::open(database)
            .await
            .map_err(Error::Unavailable.redact())
    };
    let global_db = open_db(global_db.0, global_db.1).await?;
    let template: CommunityConfig =
        serde_json::from_slice(&prepared.template).map_err(Error::Invalid.redact())?;
    let community_token = match &template.database_token_file {
        Some(path) => Some(
            String::from_utf8(Config::secret(path)?.to_vec()).map_err(Error::Invalid.redact())?,
        ),
        None => None,
    };
    let community_db = open_db(&template.database_url, community_token).await?;
    let factory = Arc::new(TemplateFactory {
        template: prepared.template,
        clock: clock.clone(),
        construction: construction.clone(),
        purpose: OnceLock::new(),
    });
    if let Some(purpose) = purpose {
        let _ = factory.purpose.set(purpose);
    }
    let hub = Hub::new(HubParts {
        global_db,
        community_db,
        issuer: prepared.issuer,
        limits: prepared.limits,
        provisioner: prepared.provisioner,
        factory: factory.clone(),
        base: base.to_owned(),
        reserved: prepared.reserved,
        clock,
        shell_seconds: prepared.shell_seconds,
        master: prepared.master,
        hold_key: prepared.hold_key,
    })
    .await?;
    let global = services.first_mut().ok_or(Error::Unavailable)?;
    global.door.attach_hub(Arc::new(hub.clone()))?;
    hub.attach_ended_sink(Arc::new(global.door.clone()))?;
    global.router = Some(hub.front(&global.door));
    global.hub = Some(hub.clone());
    hub.restore().await?;
    Ok(())
}
