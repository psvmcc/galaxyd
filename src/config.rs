use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub namespaces: Vec<NamespaceConfig>,
    #[serde(default = "default_token_dir")]
    pub token_dir: PathBuf,
    #[serde(default)]
    pub auth: AuthConfig,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            network: NetworkConfig::default(),
            namespaces: vec![],
            token_dir: default_token_dir(),
            auth: AuthConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub local: LocalAuthConfig,
    #[serde(default)]
    pub oidc: OidcConfig,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_users_file")]
    pub users_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub debug: bool,
    #[serde(default = "default_true")]
    pub request_offline_access: bool,
    #[serde(default = "default_oidc_refresh_interval")]
    pub refresh_interval_seconds: u64,
    #[serde(default)]
    pub issuer_url: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret_file: PathBuf,
    #[serde(default)]
    pub redirect_url: String,
    #[serde(default = "default_oidc_display_name")]
    pub display_name: String,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default)]
    pub group_mappings: Vec<GroupMapping>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupMapping {
    pub group: String,
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default)]
    pub admin: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            local: LocalAuthConfig::default(),
            oidc: OidcConfig::default(),
            session_ttl_seconds: default_session_ttl(),
        }
    }
}
impl Default for LocalAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            users_file: default_admin_users_file(),
        }
    }
}
impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            debug: false,
            request_offline_access: true,
            refresh_interval_seconds: default_oidc_refresh_interval(),
            issuer_url: String::new(),
            client_id: String::new(),
            client_secret_file: PathBuf::new(),
            redirect_url: String::new(),
            display_name: default_oidc_display_name(),
            groups_claim: default_groups_claim(),
            group_mappings: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_public_listener")]
    pub listen: SocketAddr,
    #[serde(default = "default_metrics_listener")]
    pub observability_listen: SocketAddr,
    #[serde(default = "default_public_url")]
    pub public_url: String,
    #[serde(default = "default_true")]
    pub ui_enabled: bool,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".parse().unwrap(),
            observability_listen: default_metrics_listener(),
            public_url: default_public_url(),
            ui_enabled: true,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum StorageConfig {
    Local {
        path: PathBuf,
    },
    S3 {
        bucket: String,
        #[serde(default)]
        prefix: String,
        #[serde(default)]
        endpoint: Option<String>,
        #[serde(default)]
        region: Option<String>,
        #[serde(default)]
        force_path_style: bool,
    },
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self::Local {
            path: PathBuf::from("/var/lib/galaxyd"),
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default)]
    pub set_real_ip_from: Vec<IpNet>,
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: usize,
    #[serde(default = "default_hops")]
    pub max_forwarded_for_hops: usize,
}
impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            set_real_ip_from: vec![],
            max_upload_bytes: default_max_upload_bytes(),
            max_forwarded_for_hops: 16,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespaceConfig {
    pub name: String,
    #[serde(default)]
    pub push_networks: Vec<IpNet>,
}

fn default_token_dir() -> PathBuf {
    PathBuf::from("/etc/galaxyd/tokens")
}
fn default_public_listener() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}
fn default_metrics_listener() -> SocketAddr {
    "127.0.0.1:9090".parse().unwrap()
}
fn default_public_url() -> String {
    "http://localhost:8080".into()
}
fn default_true() -> bool {
    true
}
fn default_hops() -> usize {
    16
}
fn default_max_upload_bytes() -> usize {
    128 * 1024 * 1024
}
fn default_session_ttl() -> u64 {
    8 * 60 * 60
}
fn default_oidc_refresh_interval() -> u64 {
    300
}
fn default_admin_users_file() -> PathBuf {
    PathBuf::from("/etc/galaxyd/admins.users")
}
fn default_groups_claim() -> String {
    "groups".into()
}
fn default_oidc_display_name() -> String {
    "OIDC".into()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        const MAX_CONFIG_BYTES: usize = 1024 * 1024;
        use std::io::Read;
        let mut file =
            std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {}", path.display()))?;
        if bytes.len() > MAX_CONFIG_BYTES {
            anyhow::bail!("configuration file exceeds 1 MiB")
        }
        let text = String::from_utf8(bytes).context("configuration file is not UTF-8")?;
        let cfg: Self = match path.extension().and_then(|e| e.to_str()) {
            Some("toml") => toml::from_str(&text).context("parsing TOML")?,
            Some("yaml" | "yml") => serde_yaml_ng::from_str(&text).context("parsing YAML")?,
            _ => anyhow::bail!("config extension must be .toml, .yaml, or .yml"),
        };
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn validate(&self) -> Result<()> {
        if self.auth.oidc.refresh_interval_seconds == 0
            || (self.auth.oidc.enabled
                && self.auth.oidc.refresh_interval_seconds >= self.auth.session_ttl_seconds)
        {
            anyhow::bail!("OIDC refresh interval must be positive and shorter than session TTL")
        }
        if self.network.max_upload_bytes == 0 || self.network.max_forwarded_for_hops == 0 {
            anyhow::bail!("network limits must be positive")
        }
        let public_url =
            url::Url::parse(&self.server.public_url).context("public_url must be a valid URL")?;
        if !matches!(public_url.scheme(), "http" | "https")
            || public_url.host().is_none()
            || !public_url.username().is_empty()
            || public_url.password().is_some()
            || public_url.query().is_some()
            || public_url.fragment().is_some()
            || self.server.public_url.ends_with('/')
        {
            anyhow::bail!(
                "public_url must be an http(s) URL without a trailing slash, query, or fragment"
            )
        }
        match &self.storage {
            StorageConfig::Local { path } if path.as_os_str().is_empty() => {
                anyhow::bail!("local storage path must not be empty")
            }
            StorageConfig::S3 { bucket, .. } if bucket.trim().is_empty() => {
                anyhow::bail!("S3 bucket must not be empty")
            }
            StorageConfig::S3 {
                endpoint: Some(endpoint),
                ..
            } => {
                let endpoint = url::Url::parse(endpoint).context("invalid S3 endpoint")?;
                if !matches!(endpoint.scheme(), "http" | "https")
                    || endpoint.host().is_none()
                    || !endpoint.username().is_empty()
                    || endpoint.password().is_some()
                    || endpoint.fragment().is_some()
                {
                    anyhow::bail!("S3 endpoint must be an absolute HTTP(S) URL")
                }
            }
            _ => {}
        }
        let mut names = HashSet::new();
        for namespace in &self.namespaces {
            if !valid_component(&namespace.name) || !names.insert(&namespace.name) {
                anyhow::bail!("invalid or duplicate namespace: {}", namespace.name)
            }
        }
        if self.server.listen == self.server.observability_listen {
            anyhow::bail!("public and observability listeners must differ")
        }
        if self.auth.session_ttl_seconds == 0 || self.auth.session_ttl_seconds > 7 * 24 * 60 * 60 {
            anyhow::bail!("auth session TTL must be between 1 second and 7 days")
        }
        if self.auth.enabled && !self.auth.local.enabled && !self.auth.oidc.enabled {
            anyhow::bail!("global authorization requires local or OIDC authentication")
        }
        if self.auth.local.enabled && self.auth.local.users_file.as_os_str().is_empty() {
            anyhow::bail!("enabled local authentication requires users_file")
        }
        if self.auth.oidc.enabled
            && (self.auth.oidc.issuer_url.is_empty()
                || self.auth.oidc.client_id.is_empty()
                || self.auth.oidc.client_secret_file.as_os_str().is_empty()
                || self.auth.oidc.redirect_url.is_empty())
        {
            anyhow::bail!(
                "enabled OIDC requires issuer_url, client_id, client_secret_file, and redirect_url"
            )
        }
        if self.auth.oidc.enabled {
            for (name, value) in [
                ("OIDC issuer_url", &self.auth.oidc.issuer_url),
                ("OIDC redirect_url", &self.auth.oidc.redirect_url),
            ] {
                let parsed = url::Url::parse(value).with_context(|| format!("invalid {name}"))?;
                if !(parsed.scheme() == "https"
                    || (parsed.scheme() == "http"
                        && parsed.host_str().is_some_and(|host| {
                            host.eq_ignore_ascii_case("localhost")
                                || host
                                    .parse::<std::net::IpAddr>()
                                    .is_ok_and(|ip| ip.is_loopback())
                        })))
                    || parsed.host().is_none()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.fragment().is_some()
                {
                    anyhow::bail!("{name} must be an absolute http(s) URL")
                }
            }
            if self.auth.oidc.groups_claim.trim().is_empty() {
                anyhow::bail!("OIDC groups_claim must not be empty")
            }
        }
        for mapping in &self.auth.oidc.group_mappings {
            if mapping.group.is_empty() || (mapping.admin && !mapping.namespaces.is_empty()) {
                anyhow::bail!("invalid OIDC group mapping")
            }
            for namespace in &mapping.namespaces {
                if !names.contains(namespace) {
                    anyhow::bail!("OIDC group mapping references unknown namespace: {namespace}")
                }
            }
        }
        Ok(())
    }
}
fn valid_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_duplicate_namespaces() {
        let c = Config {
            namespaces: vec![
                NamespaceConfig {
                    name: "a".into(),
                    push_networks: vec![],
                },
                NamespaceConfig {
                    name: "a".into(),
                    push_networks: vec![],
                },
            ],
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn loads_toml_and_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("config.toml");
        std::fs::write(&toml_path, "[server]\nlisten = '127.0.0.1:8080'\nobservability_listen = '127.0.0.1:9090'\n[[namespaces]]\nname = 'engineering'\n").unwrap();
        assert_eq!(
            Config::load(&toml_path).unwrap().namespaces[0].name,
            "engineering"
        );
        let yaml_path = dir.path().join("config.yaml");
        std::fs::write(&yaml_path, "server:\n  listen: 127.0.0.1:8081\n  observability_listen: 127.0.0.1:9091\nnamespaces:\n  - name: platform\n").unwrap();
        assert_eq!(
            Config::load(&yaml_path).unwrap().namespaces[0].name,
            "platform"
        );
    }

    #[test]
    fn rejects_invalid_extension_and_same_listener() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        assert!(Config::load(&path).is_err());
        let mut config = Config::default();
        config.server.observability_listen = config.server.listen;
        assert!(config.validate().is_err());
    }

    #[test]
    fn network_section_keeps_upload_default() {
        let config: Config = toml::from_str("[network]\nset_real_ip_from = []\n").unwrap();
        assert_eq!(config.network.max_upload_bytes, 128 * 1024 * 1024);
    }

    #[test]
    fn rejects_oversized_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn oidc_refresh_interval_must_precede_session_expiry() {
        let mut cfg = Config::load(Path::new("config/galaxyd.auth.oidc.example.toml")).unwrap();
        assert!(cfg.validate().is_ok());
        cfg.auth.oidc.refresh_interval_seconds = cfg.auth.session_ttl_seconds;
        assert!(cfg.validate().is_err());
        cfg.auth.oidc.refresh_interval_seconds = 0;
        assert!(cfg.validate().is_err());
    }
}
