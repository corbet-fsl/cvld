//! Explicit operator-selected service roots; no host mux or credential migration.
use super::*;
use serde::Deserialize;
use std::{collections::BTreeSet, net::SocketAddr};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Files {
    root_board_config: String,
    source_configs: Vec<String>,
    purpose_key_file: String,
}

pub(super) struct Prepared {
    pub root: RootCommunityConfig,
    pub sources: Vec<CommunityConfig>,
    pub key: cpsd::IssuerKey,
    pub budget: Duration,
}

pub(super) fn read(path: &str) -> Result<Prepared> {
    let files: Files =
        serde_json::from_slice(&std::fs::read(path).map_err(Error::Unavailable.redact())?)
            .map_err(Error::Invalid.redact())?;
    if files.source_configs.is_empty() || files.purpose_key_file.is_empty() {
        return Err(Error::Invalid);
    }
    let root = RootCommunityConfig::read(&files.root_board_config)?;
    let mut budget = root.shutdown_budget()?;
    let mut binds = BTreeSet::new();
    bind(&mut binds, root.listen())?;
    let mut names = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    hosts.insert(host(root.community_name(), root.domain())?);
    hosts.insert(host(&format!("admin.{}", root.community_name()), root.domain())?);
    let mut sources = Vec::new();
    for path in files.source_configs {
        let source = CommunityConfig::read(&path)?;
        if source.community == root.community_name()
            || source.domain != root.domain()
            || !names.insert(source.community.clone())
        {
            return Err(Error::Invalid);
        }
        for scope in [
            source.community.clone(),
            format!("admin.{}", source.community),
        ] {
            if !hosts.insert(host(&scope, &source.domain)?) {
                return Err(Error::Invalid);
            }
        }
        bind(&mut binds, &source.listen)?;
        budget = budget.min(source.shutdown_budget()?);
        sources.push(source);
    }
    let key = cpsd::IssuerKey::from_secret_bytes(&Config::secret(&files.purpose_key_file)?)
        .map_err(Error::Invalid.redact())?;
    Ok(Prepared {
        root,
        sources,
        key,
        budget,
    })
}

fn bind(used: &mut BTreeSet<SocketAddr>, input: &str) -> Result<()> {
    let address: SocketAddr = input.parse().map_err(Error::Invalid.redact())?;
    if used.iter().any(|other| {
        other.port() == address.port()
            && (other.ip().to_canonical() == address.ip().to_canonical()
                || other.ip().is_unspecified()
                || address.ip().is_unspecified())
    }) {
        return Err(Error::Invalid);
    }
    used.insert(address);
    Ok(())
}

pub(crate) fn host(scope: &str, domain: &str) -> Result<String> {
    let name = format!("api.{scope}.{domain}");
    let parsed = url::Url::parse(&format!("https://{name}")).map_err(Error::Invalid.redact())?;
    if parsed.host_str() != Some(name.as_str())
        || parsed.path() != "/"
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(Error::Invalid);
    }
    Ok(name)
}
