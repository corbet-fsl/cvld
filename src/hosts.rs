//! Hostname provisioning for communities: a port called when a community is
//! created and when it ends. Adapters are a no-op/recording one for tests and CI
//! and a Cloudflare one (custom domains on the two existing static Workers).
//! Credentials come only from the deployment configuration, never from a request.
use crate::error::{Error, Result};
use std::{future::Future, pin::Pin, sync::Mutex};

pub type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The two hostnames of a community under the platform base domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hostnames {
    pub community: String,
    pub vault: String,
}

impl Hostnames {
    /// `<address>.<base>` and `vault.<address>.<base>`.
    pub fn new(address: &str, base: &str) -> Self {
        Self {
            community: format!("{address}.{base}"),
            vault: format!("vault.{address}.{base}"),
        }
    }
}

pub trait HostProvisioner: Send + Sync {
    /// Make both hostnames resolve to the community front. Must be idempotent.
    fn provision<'a>(&'a self, hosts: &'a Hostnames) -> Boxed<'a, Result<()>>;
    /// Remove both hostnames. Must be idempotent and succeed when already gone.
    fn deprovision<'a>(&'a self, hosts: &'a Hostnames) -> Boxed<'a, Result<()>>;
}

/// Records calls; used by tests and by deployments without managed hostnames.
#[derive(Default)]
pub struct NoopProvisioner {
    calls: Mutex<Vec<(bool, Hostnames)>>,
}

impl NoopProvisioner {
    /// `(provisioned, hosts)` in call order.
    pub fn calls(&self) -> Vec<(bool, Hostnames)> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl HostProvisioner for NoopProvisioner {
    fn provision<'a>(&'a self, hosts: &'a Hostnames) -> Boxed<'a, Result<()>> {
        Box::pin(async move {
            self.calls
                .lock()
                .map_err(|_| Error::Unavailable)?
                .push((true, hosts.clone()));
            Ok(())
        })
    }
    fn deprovision<'a>(&'a self, hosts: &'a Hostnames) -> Boxed<'a, Result<()>> {
        Box::pin(async move {
            self.calls
                .lock()
                .map_err(|_| Error::Unavailable)?
                .push((false, hosts.clone()));
            Ok(())
        })
    }
}

/// Cloudflare Workers custom domains. The community host is served by the
/// community Worker and the vault host by the vault Worker (both static).
pub struct CloudflareProvisioner {
    client: reqwest::Client,
    api: String,
    account: String,
    zone: String,
    token: String,
    community_worker: String,
    vault_worker: String,
}

impl CloudflareProvisioner {
    /// `token` must be a scoped API token read from the deployment secrets.
    pub fn new(
        account: String,
        zone: String,
        token: String,
        community_worker: String,
        vault_worker: String,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            client,
            api: "https://api.cloudflare.com/client/v4".to_owned(),
            account,
            zone,
            token,
            community_worker,
            vault_worker,
        })
    }

    /// Point the adapter at another API origin (tests).
    pub fn with_api(mut self, api: String) -> Self {
        self.api = api;
        self
    }

    fn domains(&self) -> String {
        format!("{}/accounts/{}/workers/domains", self.api, self.account)
    }

    async fn attach(&self, hostname: &str, service: &str) -> Result<()> {
        let response = self
            .client
            .put(self.domains())
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "hostname": hostname,
                "service": service,
                "zone_id": self.zone,
                "environment": "production",
            }))
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::Unavailable)
        }
    }

    async fn detach(&self, hostname: &str) -> Result<()> {
        let listing = self
            .client
            .get(self.domains())
            .query(&[("hostname", hostname)])
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        if !listing.status().is_success() {
            return Err(Error::Unavailable);
        }
        let body: serde_json::Value = listing.json().await.map_err(|_| Error::Unavailable)?;
        let ids: Vec<String> = body["result"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter(|item| item["hostname"] == hostname)
                    .filter_map(|item| item["id"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        for id in ids {
            let response = self
                .client
                .delete(format!("{}/{id}", self.domains()))
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(|_| Error::Unavailable)?;
            if !response.status().is_success() && response.status().as_u16() != 404 {
                return Err(Error::Unavailable);
            }
        }
        Ok(())
    }
}

impl HostProvisioner for CloudflareProvisioner {
    fn provision<'a>(&'a self, hosts: &'a Hostnames) -> Boxed<'a, Result<()>> {
        Box::pin(async move {
            self.attach(&hosts.community, &self.community_worker)
                .await?;
            self.attach(&hosts.vault, &self.vault_worker).await
        })
    }
    fn deprovision<'a>(&'a self, hosts: &'a Hostnames) -> Boxed<'a, Result<()>> {
        Box::pin(async move {
            // Try both so one failure does not leave the other behind.
            let first = self.detach(&hosts.community).await;
            let second = self.detach(&hosts.vault).await;
            first.and(second)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames_follow_the_two_label_shapes() {
        let hosts = Hostnames::new("alpha123x", "cmtymeet.corbet.ch");
        assert_eq!(hosts.community, "alpha123x.cmtymeet.corbet.ch");
        assert_eq!(hosts.vault, "vault.alpha123x.cmtymeet.corbet.ch");
    }

    #[tokio::test]
    async fn noop_records_calls_in_order() {
        let port = NoopProvisioner::default();
        let hosts = Hostnames::new("gardenclub", "example.org");
        port.provision(&hosts).await.unwrap();
        port.deprovision(&hosts).await.unwrap();
        assert_eq!(port.calls(), vec![(true, hosts.clone()), (false, hosts)]);
    }
}
