//! Mesh daemon configuration, on-disk layout, and permission hardening.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Default loopback HTTP API address for the mesh daemon.
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:4620";

/// Default embedded-relay bind address (Phase 3 cutover).
pub const DEFAULT_RELAY_BIND: &str = "0.0.0.0:3340";

/// Default loopback health endpoint of `NotesSync.app` (vault sync).
pub const DEFAULT_NOTES_HEALTH_URL: &str = "http://127.0.0.1:8082/health";

fn default_listen_addr() -> String {
    DEFAULT_LISTEN_ADDR.to_string()
}

fn default_relay_bind() -> Option<String> {
    Some(DEFAULT_RELAY_BIND.to_string())
}

fn default_notes_health_url() -> String {
    DEFAULT_NOTES_HEALTH_URL.to_string()
}

/// Per-app forwarding target: either a loopback `port` or a `base_url`.
///
/// `base_url` is accepted so existing `config.toml` files written against the
/// spec (`base_url = "http://127.0.0.1:22091"`) parse cleanly; the port is
/// extracted from it when `port` is omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppTargetConfig {
    /// Loopback TCP port of the local app (e.g. `feeds` on 4610).
    #[serde(default)]
    pub port: Option<u16>,
    /// Loopback base URL; the port is derived from it when `port` is absent.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Read-only apps accept only `GET`/`HEAD` across the mesh (e.g. `notes`).
    #[serde(default)]
    pub read_only: bool,
}

impl AppTargetConfig {
    pub fn new(port: u16) -> Self {
        Self {
            port: Some(port),
            base_url: None,
            read_only: false,
        }
    }

    pub fn read_only(port: u16) -> Self {
        Self {
            port: Some(port),
            base_url: None,
            read_only: true,
        }
    }

    pub fn from_base_url(base_url: impl Into<String>) -> Self {
        Self {
            port: None,
            base_url: Some(base_url.into()),
            read_only: false,
        }
    }

    /// The loopback port to forward to: `port` if set, else parsed from
    /// `base_url`.
    pub fn resolved_port(&self) -> Result<u16> {
        if let Some(p) = self.port {
            return Ok(p);
        }
        let url = self
            .base_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("app target has neither port nor base_url"))?;
        let after_scheme = url
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(url);
        let authority = after_scheme.split(['/', '?']).next().unwrap_or(after_scheme);
        let port_str = authority
            .rsplit_once(':')
            .map(|(_, p)| p)
            .ok_or_else(|| anyhow::anyhow!("base_url {url:?} has no port"))?;
        port_str
            .parse::<u16>()
            .with_context(|| format!("base_url {url:?} has an invalid port"))
    }
}

/// Parsed `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshConfig {
    pub device_name: String,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default)]
    pub known_public_relays: Vec<String>,
    /// Start the embedded relay. Defaults to **false**: on umbra, NotesSync
    /// already holds `0.0.0.0:3340`, so a default-on relay would fail to bind.
    #[serde(default)]
    pub relay_listen: bool,
    #[serde(default = "default_relay_bind")]
    pub relay_bind: Option<String>,
    /// Loopback health URL of `NotesSync.app`; `/status` probes it with a
    /// 500ms timeout to report `notes_sync_healthy`.
    #[serde(default = "default_notes_health_url")]
    pub notes_health_url: String,
    #[serde(default)]
    pub apps: BTreeMap<String, AppTargetConfig>,
}

impl MeshConfig {
    pub fn new(device_name: impl Into<String>) -> Self {
        Self {
            device_name: device_name.into(),
            listen_addr: default_listen_addr(),
            known_public_relays: Vec::new(),
            relay_listen: false,
            relay_bind: default_relay_bind(),
            notes_health_url: default_notes_health_url(),
            apps: BTreeMap::new(),
        }
    }

    /// Parse `config.toml` text.
    pub fn from_toml(text: &str) -> Result<Self> {
        let cfg: MeshConfig = toml::from_str(text).context("parse mesh config.toml")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serialize mesh config.toml")
    }

    pub fn validate(&self) -> Result<()> {
        if self.device_name.trim().is_empty() {
            bail!("device_name must not be empty");
        }
        if self.device_name.len() > 64 {
            bail!("device_name must be at most 64 bytes");
        }
        for (name, app) in &self.apps {
            app.resolved_port()
                .with_context(|| format!("app {name:?} target"))?;
        }
        Ok(())
    }
}

/// Canonical on-disk paths for one mesh data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPaths {
    pub dir: PathBuf,
    pub key: PathBuf,
    pub lock: PathBuf,
    pub allowlist: PathBuf,
    pub config: PathBuf,
}

impl MeshPaths {
    pub fn at(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        Self {
            key: dir.join("secret.key"),
            lock: dir.join("mesh.lock"),
            allowlist: dir.join("allowlist.json"),
            config: dir.join("config.toml"),
            dir,
        }
    }

    /// `~/.config/webdesserts/mesh` (or the platform equivalent).
    pub fn default_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("webdesserts")
            .join("mesh")
    }

    pub fn default_paths() -> Self {
        Self::at(Self::default_dir())
    }

    /// Create the data directory with mode `0700` on Unix.
    pub fn ensure_dir(&self) -> Result<()> {
        create_dir_0700(&self.dir)
    }

    pub fn load_config(&self) -> Result<MeshConfig> {
        let text = std::fs::read_to_string(&self.config)
            .with_context(|| format!("read {}", self.config.display()))?;
        MeshConfig::from_toml(&text)
    }

    pub fn save_config(&self, cfg: &MeshConfig) -> Result<()> {
        cfg.validate()?;
        self.ensure_dir()?;
        let text = cfg.to_toml()?;
        write_file_0600(&self.config, text.as_bytes())
    }
}

/// Create `dir` (and parents) with mode `0700` on Unix.
pub fn create_dir_0700(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::PermissionsExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(dir)
            .with_context(|| format!("create dir {}", dir.display()))?;
        // `recursive(true)` keeps existing modes; force the leaf to 0700.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).with_context(|| format!("create dir {}", dir.display()))
    }
}

/// Write a file with mode `0600` on Unix.
pub fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut f = opts
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
    }
}
