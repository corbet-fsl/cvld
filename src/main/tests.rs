use super::*;

#[tokio::test]
async fn execution_refuses_an_incomplete_or_extended_command_tree() {
    let matches = cli::command()
        .subcommand_required(false)
        .try_get_matches_from(["cvld"])
        .unwrap();
    assert!(matches!(execute(matches).await, Err(Error::Invalid)));
    let mut command = cli::command();
    let serve = command.find_subcommand_mut("serve").unwrap();
    *serve = serve
        .clone()
        .subcommand(clap::Command::new("unknown").arg(clap::Arg::new("config").long("config")));
    let matches = command
        .try_get_matches_from(["cvld", "serve", "unknown", "--config", "never-read"])
        .unwrap();
    assert!(matches!(execute(matches).await, Err(Error::Invalid)));
}
