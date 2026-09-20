use anyhow::Result;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use clap::Parser;
use galaxyd::{
    app,
    cli::{self, Command},
    config::Config,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    let command = cli.command.unwrap_or(Command::Serve { config: cli.config });
    let oidc_debug = match &command {
        Command::Serve { config } => Config::load(config)?.auth.oidc.debug,
        _ => false,
    };
    let filter = if oidc_debug {
        tracing_subscriber::EnvFilter::new("info,galaxyd=debug")
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
    match command {
        Command::CheckConfig { config } => {
            Config::load(&config)?;
            println!("configuration is valid: {}", config.display());
        }
        Command::Healthcheck { url } => {
            let response = reqwest_get(&url).await?;
            if !response {
                anyhow::bail!("healthcheck failed")
            }
        }
        Command::PasswordHash => {
            use std::io::Read;
            let mut password = String::new();
            std::io::stdin().read_to_string(&mut password)?;
            let password = password.trim_end_matches(['\r', '\n']);
            if password.is_empty() {
                anyhow::bail!("password must not be empty");
            }
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map_err(|error| anyhow::anyhow!("password hashing failed: {error}"))?
                .to_string();
            println!("{hash}");
        }
        Command::Serve { config } => app::run(config).await?,
    }
    Ok(())
}

async fn reqwest_get(url: &str) -> Result<bool> {
    let remainder = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("healthcheck supports http:// URLs only"))?;
    let (address, path) = match remainder.split_once('/') {
        Some((host, path)) => (host.to_owned(), format!("/{path}")),
        None => (remainder.to_owned(), "/".to_owned()),
    };
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(&address),
    )
    .await
    .map_err(|_| anyhow::anyhow!("healthcheck connection timed out"))??;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_to_end(&mut response),
    )
    .await
    .map_err(|_| anyhow::anyhow!("healthcheck response timed out"))??;
    let status = response
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    Ok(status.starts_with(b"HTTP/1.1 2") || status.starts_with(b"HTTP/1.0 2"))
}
