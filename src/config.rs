//! Mesh daemon configuration, on-disk layout, and permission hardening.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use app_config::{AppPaths, ResolveOptions};
use p2p_core::daemon_lock::{DaemonLock, LockError};
use serde::{Deserialize, Serialize};

/// Default loopback HTTP API address for the mesh daemon.
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:4620";

/// Default embedded-relay bind address (Phase 3 cutover).
pub const DEFAULT_RELAY_BIND: &str = "0.0.0.0:3340";

/// Default loopback health endpoint of `NotesSync.app` (vault sync).
pub const DEFAULT_NOTES_HEALTH_URL: &str = "http://127.0.0.1:8082/health";

/// Env var pointing the daemon at an explicit data directory (tests, manual runs).
pub const MESH_DIR_ENV: &str = "MESH_DIR";

/// `app-config` env prefix: `MESH_XDG_{CONFIG,DATA,STATE,CACHE}_DIR` override each XDG root.
pub const MESH_XDG_ENV_PREFIX: &str = "MESH_XDG";

/// XDG app name: `~/.config/mesh`, `~/.local/state/mesh`.
const APP_NAME: &str = "mesh";

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
    /// Whether a `Friend` peer may reach this app (default: no).
    #[serde(default)]
    pub allow_friends: bool,
}

impl AppTargetConfig {
    pub fn new(port: u16) -> Self {
        Self {
            port: Some(port),
            base_url: None,
            read_only: false,
            allow_friends: false,
        }
    }

    pub fn read_only(port: u16) -> Self {
        Self {
            port: Some(port),
            base_url: None,
            read_only: true,
            allow_friends: false,
        }
    }

    pub fn from_base_url(base_url: impl Into<String>) -> Self {
        Self {
            port: None,
            base_url: Some(base_url.into()),
            read_only: false,
            allow_friends: false,
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
    /// Launch-at-login preference. `None` (first boot) enables the LaunchAgent
    /// and persists `Some(true)`; turning it off persists `Some(false)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autostart_enabled: Option<bool>,
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
            autostart_enabled: None,
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
    /// Signed membership log (source of truth for the allowlist projection).
    pub membership: PathBuf,
    /// Unix domain socket for local app registration (mode 0600).
    pub register_sock: PathBuf,
    /// Dynamically registered apps (token hashes only, mode 0600).
    pub registrations: PathBuf,
    /// Admin bearer token for mutating management routes over TCP (mode 0600).
    pub admin_token: PathBuf,
}

impl MeshPaths {
    pub fn at(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        Self {
            key: dir.join("secret.key"),
            lock: dir.join("mesh.lock"),
            allowlist: dir.join("allowlist.json"),
            config: dir.join("config.toml"),
            membership: dir.join("membership.json"),
            register_sock: dir.join("register.sock"),
            registrations: dir.join("registrations.json"),
            admin_token: dir.join("admin.token"),
            dir,
        }
    }

    /// XDG paths for `mesh`: config `~/.config/mesh` (0700), state
    /// `~/.local/state/mesh` (migration backups). `MESH_XDG_*_DIR` override.
    pub fn default_app_paths() -> Result<AppPaths> {
        AppPaths::resolve_with(
            APP_NAME,
            &ResolveOptions::new().env_prefix(MESH_XDG_ENV_PREFIX),
        )
        .context("resolve mesh XDG paths")
    }

    /// The data directory to run against: `MESH_DIR` when set and non-empty,
    /// else `~/.config/mesh` after [`migrate_legacy_dirs`] has moved any legacy
    /// `webdesserts/mesh` directory into place.
    pub fn resolve() -> Result<Self> {
        if let Some(dir) = std::env::var(MESH_DIR_ENV)
            .ok()
            .filter(|d| !d.trim().is_empty())
        {
            return Ok(Self::at(dir));
        }
        let app_paths = Self::default_app_paths()?;
        let home = dirs::home_dir().context("cannot determine the home directory")?;
        migrate_legacy_dirs(&home, &app_paths)
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
        app_config::write_secret_atomic(&self.config, text.as_bytes())
            .with_context(|| format!("write {}", self.config.display()))
    }
}

/// `~/.config/webdesserts/mesh`: the v0.3.0 data dir under a login shell.
fn legacy_xdg_dir(home: &Path) -> PathBuf {
    home.join(".config").join("webdesserts").join("mesh")
}

/// `~/Library/Application Support/webdesserts/mesh`: where v0.3.0 landed under
/// launchd (`dirs::config_dir()` on macOS), usually with a fresh identity.
fn legacy_appsupport_dir(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("webdesserts")
        .join("mesh")
}

/// Move a legacy mesh directory into `app_paths.config_dir()`. Never deletes
/// data: anything in the way goes to `<state>/backups/`.
///
/// - Canonical has `config.toml`: keep it.
/// - Else adopt `~/.config/webdesserts/mesh` (leaving a compatibility symlink),
///   else `~/Library/Application Support/webdesserts/mesh`. A legacy dir whose
///   `mesh.lock` is held by a running v0.3.0 daemon is returned as-is.
/// - Then archive an Application Support orphan whose `secret.key` differs from
///   (or is missing next to) the canonical one. Best-effort: logged, not fatal.
pub fn migrate_legacy_dirs(home: &Path, app_paths: &AppPaths) -> Result<MeshPaths> {
    let canonical = app_paths.config_dir().to_path_buf();
    let legacy_xdg = legacy_xdg_dir(home);
    let legacy_appsup = legacy_appsupport_dir(home);

    if !canonical.join("config.toml").is_file() {
        for legacy in [&legacy_xdg, &legacy_appsup] {
            if *legacy == canonical || !is_real_dir(legacy) || !legacy.join("config.toml").is_file()
            {
                continue;
            }
            match adopt_legacy(legacy, &canonical, app_paths)? {
                Adopted::Moved if *legacy == legacy_xdg => link_legacy(legacy, &canonical),
                Adopted::Moved => remove_empty_parent(legacy),
                Adopted::Busy => return Ok(MeshPaths::at(legacy)),
            }
            break;
        }
    }

    if let Err(err) = archive_orphan(&canonical, &legacy_appsup, app_paths) {
        tracing::warn!("mesh: could not archive {}: {err:#}", legacy_appsup.display());
    }
    Ok(MeshPaths::at(canonical))
}

enum Adopted {
    Moved,
    /// A running daemon holds the legacy `mesh.lock`.
    Busy,
}

fn adopt_legacy(legacy: &Path, canonical: &Path, app_paths: &AppPaths) -> Result<Adopted> {
    // Hold the legacy lock across the rename: no v0.3.0 daemon runs there now
    // or starts mid-move. Its Drop removes the file at the old (moved) path.
    let lock = match DaemonLock::acquire_at(&legacy.join("mesh.lock")) {
        Ok(lock) => lock,
        Err(LockError::AlreadyLocked) => return Ok(Adopted::Busy),
        Err(err) => {
            return Err(err).with_context(|| format!("lock {}", legacy.display()));
        }
    };
    if let Some(parent) = canonical.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    set_aside(canonical, app_paths, "uninitialized-canonical")?;
    std::fs::rename(legacy, canonical)
        .with_context(|| format!("move {} -> {}", legacy.display(), canonical.display()))?;
    drop(lock);
    app_paths
        .ensure_private_config_dir()
        .context("chmod 0700 mesh config dir")?;
    tracing::info!("mesh: migrated {} -> {}", legacy.display(), canonical.display());
    Ok(Adopted::Moved)
}

/// Clear `path` for a rename: drop it if it is an empty directory, else move it
/// into `<state>/backups/<label>-<unix_ts>`.
fn set_aside(path: &Path, app_paths: &AppPaths, label: &str) -> Result<()> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    if meta.is_dir() && std::fs::remove_dir(path).is_ok() {
        return Ok(());
    }
    let dest = backup_dest(app_paths, label)?;
    std::fs::rename(path, &dest)
        .with_context(|| format!("move {} -> {}", path.display(), dest.display()))
}

/// Archive a v0.3.0 Application Support orphan holding a different identity.
fn archive_orphan(canonical: &Path, orphan: &Path, app_paths: &AppPaths) -> Result<()> {
    let key = canonical.join("secret.key");
    if !key.is_file() || !is_real_dir(orphan) {
        return Ok(());
    }
    let orphan_key = orphan.join("secret.key");
    if orphan_key.is_file() && std::fs::read(&orphan_key)? == std::fs::read(&key)? {
        return Ok(());
    }
    let lock = match DaemonLock::acquire_at(&orphan.join("mesh.lock")) {
        Ok(lock) => lock,
        Err(LockError::AlreadyLocked) => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("lock {}", orphan.display())),
    };
    let dest = backup_dest(app_paths, "orphaned-appsupport")?;
    std::fs::rename(orphan, &dest)
        .with_context(|| format!("move {} -> {}", orphan.display(), dest.display()))?;
    drop(lock);
    remove_empty_parent(orphan);
    tracing::info!("mesh: archived orphan {} -> {}", orphan.display(), dest.display());
    Ok(())
}

/// A fresh `<state>/backups/<label>-<unix_ts>[-n]` path (parents 0700).
fn backup_dest(app_paths: &AppPaths, label: &str) -> Result<PathBuf> {
    let backups = app_paths
        .ensure_state_dir()
        .context("create mesh state dir")?
        .join("backups");
    create_dir_0700(&backups)?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut dest = backups.join(format!("{label}-{ts}"));
    let mut n = 1;
    while std::fs::symlink_metadata(&dest).is_ok() {
        dest = backups.join(format!("{label}-{ts}-{n}"));
        n += 1;
    }
    Ok(dest)
}

/// Best-effort `legacy -> canonical` symlink so external callers of
/// `~/.config/webdesserts/mesh/{register.sock,admin.token}` keep working.
/// Relative (`../mesh`) when canonical is the sibling `~/.config/mesh`.
fn link_legacy(legacy: &Path, canonical: &Path) {
    #[cfg(unix)]
    {
        let target = match legacy.parent().and_then(Path::parent) {
            Some(root) if root.join(APP_NAME) == canonical => PathBuf::from("../mesh"),
            _ => canonical.to_path_buf(),
        };
        if let Err(err) = std::os::unix::fs::symlink(&target, legacy) {
            tracing::warn!("mesh: could not link {}: {err}", legacy.display());
        }
    }
    #[cfg(not(unix))]
    let _ = (legacy, canonical);
}

/// Non-recursive: removes the vendor dir (`.../webdesserts`) only when empty.
fn remove_empty_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir(parent);
    }
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
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
        // `recursive(true)` keeps existing modes; force the leaf to 0700,
        // unless it is a symlink (never chmod through a link).
        let is_link = std::fs::symlink_metadata(dir)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if !is_link {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", dir.display()))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).with_context(|| format!("create dir {}", dir.display()))
    }
}

#[cfg(test)]
mod migrate_tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    /// `AppPaths` as resolved with `HOME=<home>` and no XDG vars.
    fn app_paths(home: &Path) -> AppPaths {
        let env = HashMap::from([("HOME".to_string(), home.display().to_string())]);
        AppPaths::resolve_with(
            APP_NAME,
            &ResolveOptions::new().env_prefix(MESH_XDG_ENV_PREFIX).env(env),
        )
        .unwrap()
    }

    fn seed(dir: &Path, key: &[u8]) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("config.toml"), "device_name = \"t\"\n").unwrap();
        fs::write(dir.join("secret.key"), key).unwrap();
    }

    fn backups(app: &AppPaths, label: &str) -> Vec<PathBuf> {
        let Ok(rd) = fs::read_dir(app.state_dir().join("backups")) else {
            return Vec::new();
        };
        rd.map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(label))
            .collect()
    }

    #[test]
    fn canonical_is_home_dot_config_mesh() {
        let home = tempfile::tempdir().unwrap();
        let app = app_paths(home.path());
        assert_eq!(app.config_dir(), home.path().join(".config/mesh"));
        assert_eq!(app.state_dir(), home.path().join(".local/state/mesh"));
    }

    #[test]
    fn case_a_keeps_canonical_and_leaves_legacy_alone() {
        let home = tempfile::tempdir().unwrap();
        let app = app_paths(home.path());
        seed(app.config_dir(), b"K1");
        seed(&legacy_xdg_dir(home.path()), b"K1");
        let paths = migrate_legacy_dirs(home.path(), &app).unwrap();
        assert_eq!(paths.dir, app.config_dir());
        assert!(is_real_dir(&legacy_xdg_dir(home.path())));
    }

    #[test]
    fn case_b_moves_legacy_xdg_and_links_relative() {
        let home = tempfile::tempdir().unwrap();
        let app = app_paths(home.path());
        let legacy = legacy_xdg_dir(home.path());
        seed(&legacy, b"K1");
        let paths = migrate_legacy_dirs(home.path(), &app).unwrap();
        assert_eq!(paths.dir, app.config_dir());
        assert_eq!(fs::read(app.config_dir().join("secret.key")).unwrap(), b"K1");
        assert_eq!(fs::read_link(&legacy).unwrap(), PathBuf::from("../mesh"));
        // Old callers resolve through the link.
        assert_eq!(fs::read(legacy.join("secret.key")).unwrap(), b"K1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(app.config_dir()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        // Idempotent: second run sees the symlink, not a real legacy dir.
        let again = migrate_legacy_dirs(home.path(), &app).unwrap();
        assert_eq!(again.dir, app.config_dir());
    }

    #[test]
    fn case_b_busy_lock_returns_legacy_untouched() {
        let home = tempfile::tempdir().unwrap();
        let app = app_paths(home.path());
        let legacy = legacy_xdg_dir(home.path());
        seed(&legacy, b"K1");
        let _held = DaemonLock::acquire_at(&legacy.join("mesh.lock")).unwrap();
        let paths = migrate_legacy_dirs(home.path(), &app).unwrap();
        assert_eq!(paths.dir, legacy);
        assert!(is_real_dir(&legacy));
        assert!(!app.config_dir().exists());
    }

    #[test]
    fn case_b_sets_aside_nonempty_uninitialized_canonical() {
        let home = tempfile::tempdir().unwrap();
        let app = app_paths(home.path());
        fs::create_dir_all(app.config_dir()).unwrap();
        fs::write(app.config_dir().join("stray"), b"x").unwrap();
        seed(&legacy_xdg_dir(home.path()), b"K1");
        migrate_legacy_dirs(home.path(), &app).unwrap();
        assert_eq!(fs::read(app.config_dir().join("secret.key")).unwrap(), b"K1");
        let set_aside = backups(&app, "uninitialized-canonical-");
        assert_eq!(set_aside.len(), 1);
        assert_eq!(fs::read(set_aside[0].join("stray")).unwrap(), b"x");
    }

    #[test]
    fn case_c_moves_appsupport_and_drops_empty_vendor_dir() {
        let home = tempfile::tempdir().unwrap();
        let app = app_paths(home.path());
        let appsup = legacy_appsupport_dir(home.path());
        seed(&appsup, b"K2");
        let paths = migrate_legacy_dirs(home.path(), &app).unwrap();
        assert_eq!(paths.dir, app.config_dir());
        assert_eq!(fs::read(app.config_dir().join("secret.key")).unwrap(), b"K2");
        assert!(!appsup.exists());
        assert!(!appsup.parent().unwrap().exists());
    }

    #[test]
    fn case_b_prefers_xdg_then_archives_differing_appsupport_orphan() {
        let home = tempfile::tempdir().unwrap();
        let app = app_paths(home.path());
        seed(&legacy_xdg_dir(home.path()), b"K1");
        let appsup = legacy_appsupport_dir(home.path());
        seed(&appsup, b"K2");
        migrate_legacy_dirs(home.path(), &app).unwrap();
        assert_eq!(fs::read(app.config_dir().join("secret.key")).unwrap(), b"K1");
        assert!(!appsup.exists());
        let archived = backups(&app, "orphaned-appsupport-");
        assert_eq!(archived.len(), 1);
        // Never deleted: the orphan identity is preserved byte-for-byte.
        assert_eq!(fs::read(archived[0].join("secret.key")).unwrap(), b"K2");
    }

    #[test]
    fn orphan_with_same_key_or_held_lock_is_left_alone() {
        let home = tempfile::tempdir().unwrap();
        let app = app_paths(home.path());
        seed(app.config_dir(), b"K1");
        let appsup = legacy_appsupport_dir(home.path());
        seed(&appsup, b"K1");
        migrate_legacy_dirs(home.path(), &app).unwrap();
        assert!(is_real_dir(&appsup));

        fs::write(appsup.join("secret.key"), b"K2").unwrap();
        let held = DaemonLock::acquire_at(&appsup.join("mesh.lock")).unwrap();
        migrate_legacy_dirs(home.path(), &app).unwrap();
        assert!(is_real_dir(&appsup));
        drop(held);

        migrate_legacy_dirs(home.path(), &app).unwrap();
        assert!(!appsup.exists());
        assert_eq!(backups(&app, "orphaned-appsupport-").len(), 1);
    }

    #[test]
    fn orphan_without_key_is_archived() {
        let home = tempfile::tempdir().unwrap();
        let app = app_paths(home.path());
        seed(app.config_dir(), b"K1");
        let appsup = legacy_appsupport_dir(home.path());
        fs::create_dir_all(&appsup).unwrap();
        fs::write(appsup.join("config.toml"), "").unwrap();
        migrate_legacy_dirs(home.path(), &app).unwrap();
        assert!(!appsup.exists());
        assert_eq!(backups(&app, "orphaned-appsupport-").len(), 1);
    }

    #[test]
    fn autostart_enabled_round_trips_and_is_omitted_when_none() {
        let cfg = MeshConfig::new(String::from("t"));
        let text = toml::to_string(&cfg).unwrap();
        assert!(!text.contains("autostart_enabled"));
        let mut on = cfg.clone();
        on.autostart_enabled = Some(false);
        let back: MeshConfig = toml::from_str(&toml::to_string(&on).unwrap()).unwrap();
        assert_eq!(back.autostart_enabled, Some(false));
    }
}
