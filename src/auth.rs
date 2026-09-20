use crate::{client_ip, config::NamespaceConfig};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenKind {
    Read,
    Write,
}
use subtle::{Choice, ConstantTimeEq};

pub fn bearer(headers: &axum::http::HeaderMap) -> Result<&str> {
    if headers
        .get_all(axum::http::header::AUTHORIZATION)
        .iter()
        .count()
        != 1
    {
        anyhow::bail!("exactly one authorization header is required")
    }
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .context("missing authorization")?
        .to_str()
        .context("invalid authorization")?;
    let (scheme, token) = value.split_once(' ').context("invalid authorization")?;
    if scheme != "Token" && scheme != "Bearer" || token.is_empty() {
        anyhow::bail!("unsupported authorization scheme")
    }
    Ok(token)
}

pub fn authorize(
    token_dir: &Path,
    namespace: &NamespaceConfig,
    token: &str,
    peer: IpAddr,
) -> Result<()> {
    if !client_ip::allowed(peer, &namespace.push_networks) {
        anyhow::bail!("source address is not allowed")
    }
    authorize_token_kind(token_dir, namespace, token, TokenKind::Write)
}

pub fn authorize_token(token_dir: &Path, namespace: &NamespaceConfig, token: &str) -> Result<()> {
    authorize_token_kind(token_dir, namespace, token, TokenKind::Write)
}

pub fn authorize_read(token_dir: &Path, namespace: &NamespaceConfig, token: &str) -> Result<()> {
    authorize_token_kind(token_dir, namespace, token, TokenKind::Read)
}

pub fn authorize_token_kind(
    token_dir: &Path,
    namespace: &NamespaceConfig,
    token: &str,
    kind: TokenKind,
) -> Result<()> {
    let paths = token_paths(token_dir, &namespace.name, kind);
    let existing = paths.iter().filter(|path| path.exists()).count();
    if kind == TokenKind::Write && existing > 1 {
        anyhow::bail!("multiple write token files exist for namespace")
    }
    let mut found = false;
    for path in paths {
        if !path.exists() {
            continue;
        }
        found = true;
        if verify_file(&path, token).is_ok() {
            return Ok(());
        }
    }
    if !found && kind == TokenKind::Write {
        anyhow::bail!("write token file is missing")
    }
    anyhow::bail!("invalid token")
}

fn verify_file(path: &Path, token: &str) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading token file metadata {}", path.display()))?;
    if metadata.len() > 64 * 1024 {
        anyhow::bail!("token file is too large")
    }
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("reading token file {}", path.display()))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading token file {}", path.display()))?;
    if bytes.len() > 64 * 1024 {
        anyhow::bail!("token file is too large")
    }
    let text = String::from_utf8(bytes).context("token file is not UTF-8")?;
    let wanted = digest(token);
    let mut matched = Choice::from(0);
    let mut count = 0usize;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        count += 1;
        matched |= digest(line).ct_eq(&wanted);
    }
    if count > 0 && bool::from(matched) {
        return Ok(());
    }
    anyhow::bail!("invalid token")
}

fn digest(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}
fn token_paths(dir: &Path, name: &str, kind: TokenKind) -> Vec<PathBuf> {
    match kind {
        TokenKind::Read => vec![
            dir.join(format!("{name}.read.secrets")),
            dir.join(format!("{name}.write.secrets")),
            dir.join(format!("{name}.secrets")),
        ],
        TokenKind::Write => vec![
            dir.join(format!("{name}.write.secrets")),
            dir.join(format!("{name}.secrets")),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_file_is_namespace_scoped() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.secrets"), "one\n").unwrap();
        let a = NamespaceConfig {
            name: "a".into(),
            push_networks: vec![],
        };
        let b = NamespaceConfig {
            name: "b".into(),
            push_networks: vec![],
        };
        assert!(authorize(d.path(), &a, "one", "127.0.0.1".parse().unwrap()).is_ok());
        assert!(authorize(d.path(), &b, "one", "127.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn read_and_write_tokens_have_separate_permissions() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.read.secrets"), "read\n").unwrap();
        std::fs::write(d.path().join("a.write.secrets"), "write\n").unwrap();
        let a = NamespaceConfig {
            name: "a".into(),
            push_networks: vec![],
        };
        assert!(authorize_read(d.path(), &a, "read").is_ok());
        assert!(authorize_read(d.path(), &a, "write").is_ok());
        assert!(authorize_token_kind(d.path(), &a, "read", TokenKind::Write).is_err());
        assert!(authorize_token_kind(d.path(), &a, "write", TokenKind::Write).is_ok());
    }
}
