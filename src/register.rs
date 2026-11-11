//! Layer 4: minimal local app bridge.
//!
//! Local apps register over a `0600` Unix domain socket (`register.sock`), which
//! is pre-authenticated by OS filesystem permissions. Mutating management routes
//! over loopback TCP additionally require `Authorization: Bearer <admin.token>`,
//! because Colima containers can reach host `127.0.0.1:4620` via
//! `host.docker.internal` and set `Host: 127.0.0.1`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::config::{AppTargetConfig, MeshPaths};

/// A dynamically registered app (only the token hash is stored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredApp {
    pub app_id: String,
    pub port: u16,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub allow_friends: bool,
    /// Hex SHA-256 of the bearer token; the raw token is never persisted.
    pub token_sha256: String,
}

/// On-disk `registrations.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registrations {
    #[serde(default)]
    pub apps: BTreeMap<String, RegisteredApp>,
}

/// Hex SHA-256 of a bearer token.
pub fn token_sha256(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    data_encoding::HEXLOWER.encode(&hasher.finalize())
}

/// Mint a fresh 32-byte hex bearer token.
pub fn mint_token() -> String {
    let bytes: [u8; 32] = rand::random();
    data_encoding::HEXLOWER.encode(&bytes)
}

/// Validate an `app_id`: `[a-z0-9_-]{1,32}`.
pub fn valid_app_id(app_id: &str) -> bool {
    !app_id.is_empty()
        && app_id.len() <= 32
        && app_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Owns `registrations.json` and the admin token.
pub struct RegistrationStore {
    paths: MeshPaths,
    registrations: RwLock<Registrations>,
    admin_token: String,
}

impl std::fmt::Debug for RegistrationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the admin token.
        f.debug_struct("RegistrationStore")
            .field("paths", &self.paths)
            .field("registrations", &self.registrations)
            .finish_non_exhaustive()
    }
}

impl RegistrationStore {
    /// Load `registrations.json` and the admin token (generating both if absent).
    pub async fn load_or_init(paths: MeshPaths) -> Result<Self> {
        let registrations = match std::fs::read_to_string(&paths.registrations) {
            Ok(text) => serde_json::from_str::<Registrations>(&text)
                .with_context(|| format!("parse {}", paths.registrations.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Registrations::default(),
            Err(e) => {
                return Err(e).with_context(|| format!("read {}", paths.registrations.display()));
            }
        };
        let admin_token = match std::fs::read_to_string(&paths.admin_token) {
            Ok(text) if !text.trim().is_empty() => text.trim().to_string(),
            _ => {
                let token = mint_token();
                app_config::write_secret_atomic(&paths.admin_token, token.as_bytes())
                    .context("write admin.token")?;
                token
            }
        };
        Ok(Self {
            paths,
            registrations: RwLock::new(registrations),
            admin_token,
        })
    }

    pub fn admin_token(&self) -> &str {
        &self.admin_token
    }

    /// Constant-time-ish comparison of a presented admin token.
    pub fn admin_token_matches(&self, presented: &str) -> bool {
        let a = token_sha256(presented);
        let b = token_sha256(&self.admin_token);
        a == b
    }

    pub async fn snapshot(&self) -> Registrations {
        self.registrations.read().await.clone()
    }

    pub async fn get(&self, app_id: &str) -> Option<RegisteredApp> {
        self.registrations.read().await.apps.get(app_id).cloned()
    }

    /// Verify a bearer token against a dynamically registered app.
    pub async fn verify_token(&self, app_id: &str, token: &str) -> bool {
        match self.get(app_id).await {
            Some(app) => app.token_sha256 == token_sha256(token),
            None => false,
        }
    }

    /// Register (or re-register with the current bearer) a dynamic app.
    ///
    /// Returns the freshly minted raw token. Static `config.toml` apps and ports
    /// already claimed by another app are refused with `409`.
    pub async fn register(
        &self,
        app_id: &str,
        port: u16,
        read_only: bool,
        allow_friends: bool,
        static_apps: &BTreeMap<String, AppTargetConfig>,
        reserved_ports: &[u16],
        presented_token: Option<&str>,
    ) -> Result<String> {
        if !valid_app_id(app_id) {
            bail!("app_id must match [a-z0-9_-]{{1,32}}");
        }
        if !(1024..=65535).contains(&port) {
            bail!("port must be in 1024..=65535");
        }
        if reserved_ports.contains(&port) {
            bail!("port {port} is reserved by the mesh daemon");
        }
        // S5b: no static or cross-app hijack.
        if static_apps.contains_key(app_id) {
            bail!("app_id {app_id:?} is statically configured in config.toml");
        }
        for (name, app) in static_apps {
            if app.resolved_port().ok() == Some(port) {
                bail!("port {port} is already claimed by static app {name:?}");
            }
        }
        let mut regs = self.registrations.write().await;
        for (name, app) in &regs.apps {
            if name != app_id && app.port == port {
                bail!("port {port} is already claimed by app {name:?}");
            }
        }
        // S5a: token-gated re-registration.
        if let Some(existing) = regs.apps.get(app_id) {
            let presented = presented_token
                .ok_or_else(|| anyhow::anyhow!("re-registration requires the current bearer token"))?;
            if existing.token_sha256 != token_sha256(presented) {
                bail!("re-registration bearer token does not match");
            }
        }
        let token = mint_token();
        regs.apps.insert(
            app_id.to_string(),
            RegisteredApp {
                app_id: app_id.to_string(),
                port,
                read_only,
                allow_friends,
                token_sha256: token_sha256(&token),
            },
        );
        let snapshot = regs.clone();
        drop(regs);
        self.persist(&snapshot).await?;
        Ok(token)
    }

    /// Remove a dynamic registration (requires the current bearer token).
    pub async fn unregister(&self, app_id: &str, presented_token: Option<&str>) -> Result<()> {
        let mut regs = self.registrations.write().await;
        let existing = regs
            .apps
            .get(app_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("app {app_id:?} is not registered"))?;
        let presented = presented_token
            .ok_or_else(|| anyhow::anyhow!("unregister requires the current bearer token"))?;
        if existing.token_sha256 != token_sha256(presented) {
            bail!("unregister bearer token does not match");
        }
        regs.apps.remove(app_id);
        let snapshot = regs.clone();
        drop(regs);
        self.persist(&snapshot).await
    }

    async fn persist(&self, regs: &Registrations) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(regs).context("serialize registrations.json")?;
        app_config::write_secret_atomic(&self.paths.registrations, &bytes)
            .with_context(|| format!("write {}", self.paths.registrations.display()))
    }
}

/// Remove a stale socket and bind `register.sock` with mode `0600`.
pub fn bind_register_sock(path: &Path) -> Result<tokio::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("bind {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    Ok(listener)
}

/// Short temp dir for UDS tests: macOS caps `sun_path` at 104 bytes.
pub fn short_test_dir(tag: &str) -> PathBuf {
    let rand: u32 = rand::random();
    PathBuf::from(format!("/tmp/mesh-test-{tag}-{rand:08x}"))
}

/// Shared handle used by the API.
pub type SharedRegistrations = Arc<RegistrationStore>;
