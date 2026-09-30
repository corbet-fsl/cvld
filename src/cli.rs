use crate::{
    api::{self, ACTIONS},
    error::{Error, Result},
};
use clap::{Arg, Command};
use serde_json::Value;

pub fn command() -> Command {
    let mut cmd = Command::new("cvld")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg(
            Arg::new("url")
                .long("url")
                .global(true)
                .default_value("http://127.0.0.1:8080"),
        )
        .arg(Arg::new("host").long("host").global(true))
        .arg(Arg::new("session-file").long("session-file").global(true))
        .subcommand(
            Command::new("serve")
                .subcommand_required(true)
                .subcommand(
                    Command::new("global").arg(Arg::new("config").long("config").required(true)),
                )
                .subcommand(
                    Command::new("community").arg(Arg::new("config").long("config").required(true)),
                ),
        )
        .subcommand(Command::new("openapi"))
        .subcommand(
            Command::new("mcp")
                .about("Serve MCP over local stdio, forwarding to the authenticated HTTP service"),
        );
    for action in ACTIONS {
        cmd = cmd.subcommand(
            Command::new(action.name)
                .about(action.description)
                .arg(Arg::new("request").long("request").default_value("{}")),
        );
    }
    cmd
}
#[derive(Clone)]
pub struct Client {
    client: reqwest::Client,
    base: String,
    host: String,
    token: Option<String>,
}
impl Client {
    pub fn new(base: String, host: String, token: Option<String>) -> Result<Self> {
        let url = reqwest::Url::parse(&base).map_err(|_| Error::Invalid)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(Error::Invalid);
        }
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err(Error::Invalid);
        }
        let client = reqwest::Client::builder()
            .user_agent("cvld-client")
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_owned(),
            host,
            token,
        })
    }
    pub async fn call(&self, name: &str, request: Value) -> Result<Value> {
        if api::action(name).is_none() {
            return Err(Error::Invalid);
        }
        let mut call = self
            .client
            .post(format!("{}/v1/{name}", self.base))
            .header("host", &self.host)
            .json(&request);
        if let Some(token) = &self.token {
            call = call.bearer_auth(token);
        }
        let response = call.send().await.map_err(|_| Error::Unavailable)?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                400 => Error::Invalid,
                401 => Error::Unauthorized,
                403 => Error::Forbidden,
                421 => Error::WrongHost,
                429 => Error::Throttled,
                409 => Error::Refused,
                _ => Error::Unavailable,
            });
        }
        response.json().await.map_err(|_| Error::Unavailable)
    }
}
