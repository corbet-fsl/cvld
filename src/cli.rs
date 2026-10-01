use crate::api::ACTIONS;
use clap::{Arg, Command};

pub use crate::client::HttpClient as Client;

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
