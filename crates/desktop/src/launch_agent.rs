//! Native macOS `LaunchAgent` for Launch at Login (replaces `tauri-plugin-autostart`).
//!
//! Writes `~/Library/LaunchAgents/com.webdesserts.mesh.plist` (`RunAtLoad`,
//! `KeepAlive.SuccessfulExit = false`). It never calls `launchctl bootout`: a
//! login-launched app runs *inside* that job, so a bootout would SIGTERM the
//! app itself.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};
use webdesserts_mesh::api;
use webdesserts_mesh::config::{MeshConfig, MeshPaths};

pub const LABEL: &str = "com.webdesserts.mesh";
pub const EXPECTED_BUNDLE_SUFFIX: &str = ".app/Contents/MacOS/Mesh";
/// Plist name written by `tauri-plugin-autostart` in `Mesh.app` v0.3.0.
pub const LEGACY_PLIST_NAME: &str = "Mesh";

pub struct LaunchAgent {
    dir: PathBuf,
}

impl LaunchAgent {
    /// The current user's `~/Library/LaunchAgents`.
    pub fn for_user() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .context("HOME is not set")?;
        Ok(Self::at(PathBuf::from(home).join("Library/LaunchAgents")))
    }

    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn plist_path(&self) -> PathBuf {
        self.dir.join(format!("{LABEL}.plist"))
    }

    pub fn legacy_plist_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.plist"))
    }

    pub fn is_enabled(&self) -> bool {
        self.plist_path().is_file()
    }

    /// Write the plist for the running executable. Returns `Ok(false)` (and
    /// writes nothing) when not running from an installed `Mesh.app` bundle.
    pub fn enable(&self) -> Result<bool> {
        let exe = std::env::current_exe().context("current_exe")?;
        self.enable_with_exe(&exe)
    }

    pub fn enable_with_exe(&self, exe: &Path) -> Result<bool> {
        let Some(exe) = validate_bundle_exe(exe) else {
            tracing::warn!(exe = %exe.display(), "not an installed Mesh.app bundle; skipping LaunchAgent plist");
            return Ok(false);
        };
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("create {}", self.dir.display()))?;
        let path = self.plist_path();
        let tmp = self.dir.join(format!(".{LABEL}.plist.tmp"));
        std::fs::write(&tmp, render_plist(LABEL, &exe))
            .with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("rename to {}", path.display()))?;
        Ok(true)
    }

    /// Remove the plist (takes effect at next login; never bootouts this job).
    pub fn disable(&self) -> Result<()> {
        remove_if_exists(&self.plist_path())?;
        Ok(())
    }

    /// Delete a legacy plist file without `launchctl bootout`.
    pub fn remove_legacy_plist_file(&self, name: &str) -> Result<bool> {
        remove_if_exists(&self.legacy_plist_path(name))
    }
}

fn remove_if_exists(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
    }
}

/// Canonicalize `exe` and accept it only inside an installed `.app` bundle
/// (not `target/debug`, not an AppTranslocation mount).
pub fn validate_bundle_exe(exe: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(exe).ok()?;
    is_valid_bundle_exe(&canonical).then_some(canonical)
}

fn is_valid_bundle_exe(canonical: &Path) -> bool {
    let s = canonical.to_string_lossy();
    s.ends_with(EXPECTED_BUNDLE_SUFFIX) && !s.contains("/AppTranslocation/")
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

pub fn render_plist(label: &str, exe: &Path) -> String {
    let label = xml_escape(label);
    let exe = xml_escape(&exe.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
</dict>
</plist>
"#
    )
}

/// Startup reconciliation: make `~/Library/LaunchAgents` match
/// `cfg.autostart_enabled` (default on), drop the v0.3.0 `Mesh.plist`, and
/// report the live state through `GET /status`.
pub fn reconcile(paths: &MeshPaths, cfg: &mut MeshConfig) {
    let agent = match LaunchAgent::for_user() {
        Ok(agent) => agent,
        Err(e) => {
            tracing::warn!(error = %e, "LaunchAgent unavailable");
            api::set_autostart_enabled(None);
            return;
        }
    };
    let exe = std::env::current_exe().ok();
    let enabled = reconcile_with(&agent, paths, cfg, exe.as_deref());
    api::set_autostart_enabled(Some(enabled));
}

fn reconcile_with(agent: &LaunchAgent, paths: &MeshPaths, cfg: &mut MeshConfig, exe: Option<&Path>) -> bool {
    let legacy_existed = agent.legacy_plist_path(LEGACY_PLIST_NAME).is_file();
    if cfg.autostart_enabled.unwrap_or(true) {
        // Write the new plist FIRST; drop the legacy one only once replaced, so
        // a dev build never removes the user's working login item.
        let written = match exe.map(|exe| agent.enable_with_exe(exe)) {
            Some(Ok(written)) => written,
            Some(Err(e)) => {
                tracing::warn!(error = %e, "enable LaunchAgent failed");
                false
            }
            None => false,
        };
        if written {
            remove_legacy(agent, legacy_existed);
        }
        if cfg.autostart_enabled.is_none() {
            cfg.autostart_enabled = Some(true);
            if let Err(e) = paths.save_config(cfg) {
                tracing::warn!(error = %e, "persist autostart_enabled failed");
            }
        }
    } else {
        if let Err(e) = agent.disable() {
            tracing::warn!(error = %e, "disable LaunchAgent failed");
        }
        remove_legacy(agent, legacy_existed);
    }
    agent.is_enabled()
}

fn remove_legacy(agent: &LaunchAgent, existed: bool) {
    if !existed {
        return;
    }
    match agent.remove_legacy_plist_file(LEGACY_PLIST_NAME) {
        Ok(_) => tracing::info!("removed legacy Mesh.plist LaunchAgent"),
        Err(e) => tracing::warn!(error = %e, "remove legacy Mesh.plist failed"),
    }
}

/// Tray `Launch at Login` toggle: flip the plist, persist the choice, report it.
pub async fn toggle(app: &AppHandle) -> Result<bool> {
    let agent = LaunchAgent::for_user()?;
    let new_state = !agent.is_enabled();
    if new_state {
        if !agent.enable()? {
            bail!("not running from an installed Mesh.app; Launch at Login unavailable");
        }
    } else {
        agent.disable()?;
    }
    let state = app.state::<crate::state::AppState>();
    let mut cfg = state.cfg.lock().await;
    cfg.autostart_enabled = Some(new_state);
    state.paths.save_config(&cfg)?;
    api::set_autostart_enabled(Some(new_state));
    Ok(new_state)
}

fn should_kickstart(xpc_service_name: Option<&str>) -> bool {
    xpc_service_name == Some(LABEL)
}

/// Relaunch after `shutdown_host`. Under launchd (`XPC_SERVICE_NAME` is our
/// label) `kickstart -k` keeps crash supervision; `app.restart()` would spawn
/// an unmanaged child. Falls back to `app.restart()` otherwise.
pub fn relaunch_app(app: &AppHandle) {
    if should_kickstart(std::env::var("XPC_SERVICE_NAME").ok().as_deref()) {
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        let target = format!("gui/{uid}/{LABEL}");
        match std::process::Command::new("/bin/launchctl")
            .args(["kickstart", "-k", &target])
            .status()
        {
            Ok(status) if status.success() => {
                tracing::info!(%target, "launchd kickstart requested");
                return;
            }
            Ok(status) => tracing::warn!(%status, "launchctl kickstart failed; falling back to restart"),
            Err(e) => tracing::warn!(error = %e, "launchctl kickstart failed; falling back to restart"),
        }
    }
    app.restart();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mesh-la-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fake_bundle(root: &Path) -> PathBuf {
        let exe = root.join("Applications/Mesh.app/Contents/MacOS/Mesh");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"").unwrap();
        exe
    }

    #[test]
    fn render_plist_escapes_and_keeps_alive_on_failure() {
        let text = render_plist(LABEL, Path::new("/Apps/A&B <x>.app/Contents/MacOS/Mesh"));
        assert!(text.contains("<string>com.webdesserts.mesh</string>"));
        assert!(text.contains("<string>/Apps/A&amp;B &lt;x&gt;.app/Contents/MacOS/Mesh</string>"));
        assert!(text.contains("<key>RunAtLoad</key>\n  <true/>"));
        assert!(text.contains("<key>SuccessfulExit</key>\n    <false/>"));
    }

    #[test]
    fn bundle_exe_validation() {
        assert!(is_valid_bundle_exe(Path::new("/Applications/Mesh.app/Contents/MacOS/Mesh")));
        assert!(!is_valid_bundle_exe(Path::new("/x/target/debug/mesh-desktop")));
        assert!(!is_valid_bundle_exe(Path::new(
            "/private/var/folders/x/AppTranslocation/ABC/d/Mesh.app/Contents/MacOS/Mesh"
        )));
        assert!(!is_valid_bundle_exe(Path::new("/Applications/Mesh.app/Contents/MacOS/webdesserts-mesh")));
    }

    #[test]
    fn kickstart_only_under_our_launchd_label() {
        assert!(should_kickstart(Some(LABEL)));
        assert!(!should_kickstart(Some("Mesh")));
        assert!(!should_kickstart(None));
    }

    #[test]
    fn enable_disable_and_invalid_exe() {
        let root = tmp("enable");
        let agent = LaunchAgent::at(root.join("LaunchAgents"));
        assert!(!agent.enable_with_exe(&root.join("target/debug/mesh")).unwrap());
        assert!(!agent.is_enabled());
        // A symlink into the bundle resolves to the real binary.
        let exe = fake_bundle(&root);
        let link = root.join("mesh-link");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        assert!(agent.enable_with_exe(&link).unwrap());
        let text = std::fs::read_to_string(agent.plist_path()).unwrap();
        assert!(text.contains(&std::fs::canonicalize(&exe).unwrap().to_string_lossy().to_string()));
        agent.disable().unwrap();
        assert!(!agent.is_enabled());
        agent.disable().unwrap();
    }

    #[test]
    fn reconcile_default_on_replaces_legacy_and_persists() {
        let root = tmp("rec-on");
        let agent = LaunchAgent::at(root.join("LaunchAgents"));
        std::fs::create_dir_all(root.join("LaunchAgents")).unwrap();
        std::fs::write(agent.legacy_plist_path("Mesh"), b"legacy").unwrap();
        let paths = MeshPaths::at(root.join("cfg"));
        let mut cfg = MeshConfig::new(String::from("t"));
        let exe = fake_bundle(&root);
        assert!(reconcile_with(&agent, &paths, &mut cfg, Some(&exe)));
        assert!(!agent.legacy_plist_path("Mesh").exists());
        assert_eq!(cfg.autostart_enabled, Some(true));
        assert_eq!(paths.load_config().unwrap().autostart_enabled, Some(true));
    }

    #[test]
    fn reconcile_dev_build_keeps_legacy() {
        let root = tmp("rec-dev");
        let agent = LaunchAgent::at(root.join("LaunchAgents"));
        std::fs::create_dir_all(root.join("LaunchAgents")).unwrap();
        std::fs::write(agent.legacy_plist_path("Mesh"), b"legacy").unwrap();
        let paths = MeshPaths::at(root.join("cfg"));
        let mut cfg = MeshConfig::new(String::from("t"));
        assert!(!reconcile_with(&agent, &paths, &mut cfg, Some(&root.join("target/debug/mesh"))));
        assert!(agent.legacy_plist_path("Mesh").exists());
    }

    #[test]
    fn reconcile_off_disables_and_removes_legacy() {
        let root = tmp("rec-off");
        let agent = LaunchAgent::at(root.join("LaunchAgents"));
        let exe = fake_bundle(&root);
        assert!(agent.enable_with_exe(&exe).unwrap());
        std::fs::write(agent.legacy_plist_path("Mesh"), b"legacy").unwrap();
        let paths = MeshPaths::at(root.join("cfg"));
        let mut cfg = MeshConfig::new(String::from("t"));
        cfg.autostart_enabled = Some(false);
        assert!(!reconcile_with(&agent, &paths, &mut cfg, Some(&exe)));
        assert!(!agent.is_enabled());
        assert!(!agent.legacy_plist_path("Mesh").exists());
        assert_eq!(cfg.autostart_enabled, Some(false));
    }
}
