use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "galaxyd", version, about = "Ansible Galaxy collection server")]
pub struct Cli {
    #[arg(long, global = true, default_value = "/etc/galaxyd/galaxyd.toml")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    CheckConfig {
        #[arg(long, default_value = "/etc/galaxyd/galaxyd.toml")]
        config: PathBuf,
    },
    Healthcheck {
        #[arg(long)]
        url: String,
    },
    PasswordHash,
}
