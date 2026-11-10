//! `Mesh.app` — a macOS menu-bar (accessory) tray app that hosts the
//! `webdesserts-mesh` daemon in-process, or attaches to an external one.

mod api_client;
mod commands;
mod control;
mod daemon_host;
mod menu_events;
mod pair_window;
mod shutdown;
mod snapshot;
mod state;
mod tray;

use anyhow::{Context, Result};
use daemon_host::DaemonHost;
use state::AppState;
use std::sync::Arc;
use std::time::Duration;
use tauri::Manager;
use tauri_plugin_autostart::ManagerExt;
use webdesserts_mesh::api;
use webdesserts_mesh::config::{MeshConfig, MeshPaths};

/// Resolve the mesh data directory: `MESH_DIR` override, else the default
/// `~/.config/webdesserts/mesh`.
fn resolve_paths() -> MeshPaths {
    match std::env::var("MESH_DIR") {
        Ok(dir) if !dir.trim().is_empty() => MeshPaths::at(dir),
        _ => MeshPaths::default_paths(),
    }
}

/// Detect the local machine name for a first-run `config.toml`.
///
/// Order: `MESH_DEVICE_NAME`, `scutil --get LocalHostName`, `hostname`, `"mac"`.
fn detect_device_name() -> String {
    if let Ok(name) = std::env::var("MESH_DEVICE_NAME") {
        let name = sanitize(&name);
        if !name.is_empty() {
            return name;
        }
    }
    for (cmd, args) in [("scutil", vec!["--get", "LocalHostName"]), ("hostname", vec![])] {
        if let Ok(out) = std::process::Command::new(cmd).args(&args).output() {
            if out.status.success() {
                let name = sanitize(&String::from_utf8_lossy(&out.stdout));
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }
    "mac".to_string()
}

/// Trim, drop a trailing `.local`, and keep only a non-empty printable name.
fn sanitize(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches(".local").trim();
    trimmed
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Create `config.toml` on first launch so a fresh Homebrew install works with
/// zero CLI setup.
fn ensure_default_config(paths: &MeshPaths) -> Result<MeshConfig> {
    if paths.config.exists() {
        return paths.load_config().context("load mesh config.toml");
    }
    let cfg = MeshConfig::new(detect_device_name());
    cfg.validate().context("validate first-run mesh config")?;
    paths.ensure_dir().context("create mesh data dir")?;
    paths.save_config(&cfg).context("write first-run config.toml")?;
    tracing::info!(device = %cfg.device_name, dir = %paths.dir.display(), "wrote first-run config.toml");
    Ok(cfg)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let paths = resolve_paths();
    let cfg = ensure_default_config(&paths)?;

    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            commands::daemon_snapshot,
            commands::generate_pair_code,
            commands::pair_with_peer,
            commands::remove_member,
            commands::copy_node_id_command,
        ])
        .setup(move |app| {
            // Menu-bar only: no Dock icon, no app switcher entry.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Launch at Login: enable on first run, then report the live state
            // through `GET /status` (`autostart_enabled`).
            let _ = app.autolaunch().enable();
            api::set_autostart_enabled(app.autolaunch().is_enabled().ok());

            let handle = app.handle().clone();
            let paths = paths.clone();
            let cfg = cfg.clone();
            let token_path = paths.admin_token.clone();
            let base = api_client::base_url(&cfg.listen_addr);

            // Start (or attach to) the daemon before the tray renders, so the
            // first menu already shows real status.
            let start_paths = paths.clone();
            let start_cfg = cfg.clone();
            let control_router = control::router(handle.clone());
            let host = tauri::async_runtime::block_on(async move {
                let host = DaemonHost::start(start_paths, start_cfg, control_router).await?;
                let token = api_client::read_admin_token(&token_path).ok();
                Ok::<_, anyhow::Error>((host, token))
            })?;
            let (host, token) = host;
            let client = api_client::Client::new(base, token);

            app.manage(AppState {
                client,
                host: tokio::sync::Mutex::new(Some(Arc::new(host))),
                paths: paths.clone(),
                cfg: tokio::sync::Mutex::new(cfg.clone()),
                last_menu: tokio::sync::Mutex::new(String::new()),
            });

            tray::build(&handle)?;

            // Refresh the tray every 3s.
            let refresh_handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tray::refresh(&refresh_handle).await;
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            });

            // SIGINT / SIGTERM: shut the daemon down cleanly, then exit.
            let signal_handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{SignalKind, signal};
                    let mut int = match signal(SignalKind::interrupt()) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(error = %e, "install SIGINT handler failed");
                            return;
                        }
                    };
                    let mut term = match signal(SignalKind::terminate()) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(error = %e, "install SIGTERM handler failed");
                            return;
                        }
                    };
                    tokio::select! {
                        _ = int.recv() => tracing::info!("SIGINT received"),
                        _ = term.recv() => tracing::info!("SIGTERM received"),
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = tokio::signal::ctrl_c().await;
                }
                shutdown::shutdown_host(&signal_handle).await;
                signal_handle.exit(0);
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .map_err(|e| anyhow::anyhow!("Tauri application error: {e}"))?
        .run(|app, event| {
            // Tray-only app: closing the pair window must not exit. Tauri fires
            // ExitRequested with code=None when the last window closes; only a
            // real exit (Quit Mesh calls app.exit(0)) carries Some(code).
            match &event {
                tauri::RunEvent::ExitRequested { code: None, api, .. } => api.prevent_exit(),
                tauri::RunEvent::ExitRequested { code: Some(_), .. } => {
                    let app = app.clone();
                    tauri::async_runtime::block_on(shutdown::shutdown_host(&app));
                }
                _ => {}
            }
        });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_trims_and_strips_local_suffix() {
        assert_eq!(sanitize("  umbra.local\n"), "umbra");
        assert_eq!(sanitize("rhea"), "rhea");
        assert_eq!(sanitize("   "), "");
        assert_eq!(sanitize("a\u{0}b"), "ab");
    }

    #[test]
    fn sanitize_caps_at_64_chars() {
        let long = "x".repeat(80);
        assert_eq!(sanitize(&long).len(), 64);
    }

    #[test]
    fn resolve_paths_honors_mesh_dir() {
        // SAFETY: single-threaded test process; restored immediately.
        unsafe { std::env::set_var("MESH_DIR", "/tmp/mesh-dir-test") };
        let paths = resolve_paths();
        unsafe { std::env::remove_var("MESH_DIR") };
        assert_eq!(paths.dir, std::path::PathBuf::from("/tmp/mesh-dir-test"));
        assert_eq!(paths.config, std::path::PathBuf::from("/tmp/mesh-dir-test/config.toml"));
    }

    #[test]
    fn ensure_default_config_creates_then_loads() {
        let dir = std::env::temp_dir().join(format!("mesh-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = MeshPaths::at(&dir);
        let cfg = ensure_default_config(&paths).unwrap();
        assert!(!cfg.device_name.trim().is_empty());
        assert!(paths.config.exists());
        let again = ensure_default_config(&paths).unwrap();
        assert_eq!(again.device_name, cfg.device_name);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
