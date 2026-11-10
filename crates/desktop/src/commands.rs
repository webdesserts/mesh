//! Tauri commands backing the pairing window, plus tray actions.
//!
//! Every mutating call goes through the daemon's loopback TCP API with the
//! admin bearer token, exactly like an external client would.

use crate::daemon_host::DaemonHost;
use crate::snapshot;
use crate::state::AppState;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::{AppHandle, Manager, State};

/// `GET /status` + `GET /membership` for the pairing window.
pub async fn snapshot(state: &AppState) -> Result<Value> {
    let snap = snapshot::fetch(&state.client).await?;
    Ok(json!({ "status": snap.status, "membership": snap.membership }))
}

/// `POST /pair/code` — arm a single-use 6-digit code (300s TTL).
pub async fn generate_code(state: &AppState) -> Result<Value> {
    state.client.post_json("/pair/code", json!({})).await
}

/// `POST /pair` — outbound pairing against a peer `node_id` + 6-digit code.
///
/// `relationship` is accepted for the UI contract but the daemon's `/pair`
/// route has no such field: `membership_sync::pair_sync_initiator` always signs
/// `Relationship::SelfDevice` (membership_sync.rs:438).
pub async fn pair(
    state: &AppState,
    peer_id: &str,
    code: &str,
    relay_url: Option<&str>,
    relationship: &str,
) -> Result<Value> {
    let peer = peer_id.trim();
    let code = code.trim();
    if peer.is_empty() {
        anyhow::bail!("peer node id is required");
    }
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!("pairing code must be exactly 6 digits");
    }
    let relay = relay_url.map(str::trim).filter(|s| !s.is_empty());
    let body = json!({
        "peer": peer,
        "code": code,
        "relay_url": relay,
        "relationship": relationship,
    });
    state.client.post_json("/pair", body).await
}

/// `POST /membership/remove` — revoke a member.
pub async fn remove(state: &AppState, peer_id: &str) -> Result<Value> {
    let peer = peer_id.trim();
    if peer.is_empty() {
        anyhow::bail!("peer node id is required");
    }
    state.client.post_json("/membership/remove", json!({ "peer": peer })).await
}

/// Copy the full local `NodeId` to the macOS pasteboard (`pbcopy`).
pub async fn copy_node_id(state: &AppState) -> Result<String> {
    let status = state.client.get_json("/status").await?;
    let node_id = status
        .get("peer_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if node_id.is_empty() {
        anyhow::bail!("daemon did not report a node id");
    }
    copy_to_pasteboard(&node_id)?;
    Ok(node_id)
}

#[cfg(target_os = "macos")]
fn copy_to_pasteboard(text: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("pbcopy")
        .stdin(Stdio::piped())
        .spawn()
        .context("spawn pbcopy")?;
    child
        .stdin
        .as_mut()
        .context("pbcopy stdin")?
        .write_all(text.as_bytes())
        .context("write to pbcopy")?;
    let status = child.wait().context("wait for pbcopy")?;
    if !status.success() {
        anyhow::bail!("pbcopy exited with {status}");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn copy_to_pasteboard(_text: &str) -> Result<()> {
    anyhow::bail!("clipboard copy is macOS-only")
}

/// Flip `relay_bind` in `config.toml` and restart the in-process daemon.
///
/// Returns whether the relay is now hosted. In attached mode the config is
/// written but the external daemon keeps its own relay setting.
pub async fn toggle_relay(app: &AppHandle) -> Result<bool> {
    let state = app.state::<AppState>();
    let mut cfg = state.cfg.lock().await.clone();
    let hosting = cfg.relay_bind.is_none();
    cfg.relay_bind = if hosting {
        Some("0.0.0.0:3340".to_string())
    } else {
        None
    };
    cfg.relay_listen = hosting;
    cfg.validate().context("validate mesh config")?;
    state.paths.save_config(&cfg).context("save config.toml")?;
    *state.cfg.lock().await = cfg.clone();

    let host = {
        let mut guard = state.host.lock().await;
        guard.take()
    };
    if let Some(host) = host {
        host.shutdown().await;
        let restarted = Arc::new(
            DaemonHost::start(state.paths.clone(), cfg)
                .await
                .context("restart mesh daemon")?,
        );
        *state.host.lock().await = Some(restarted);
    }
    Ok(hosting)
}

#[tauri::command]
pub async fn daemon_snapshot(state: State<'_, AppState>) -> Result<Value, String> {
    snapshot(&state).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn generate_pair_code(state: State<'_, AppState>) -> Result<Value, String> {
    generate_code(&state).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn pair_with_peer(
    state: State<'_, AppState>,
    peer_id: String,
    code: String,
    relay_url: Option<String>,
    relationship: Option<String>,
) -> Result<Value, String> {
    pair(
        &state,
        &peer_id,
        &code,
        relay_url.as_deref(),
        relationship.as_deref().unwrap_or("self"),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_member(state: State<'_, AppState>, peer_id: String) -> Result<Value, String> {
    remove(&state, &peer_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn copy_node_id_command(state: State<'_, AppState>) -> Result<String, String> {
    copy_node_id(&state).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_rejects_bad_code_before_network() {
        // Validation runs before any HTTP call, so a dummy client is enough.
        let client = crate::api_client::Client::new("http://127.0.0.1:1".to_string(), None);
        let state = AppState {
            client,
            host: tokio::sync::Mutex::new(None),
            paths: webdesserts_mesh::config::MeshPaths::at("/tmp/mesh-test"),
            cfg: tokio::sync::Mutex::new(webdesserts_mesh::config::MeshConfig::new("test")),
            last_menu: tokio::sync::Mutex::new(String::new()),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(rt.block_on(pair(&state, "", "123456", None, "self")).is_err());
        assert!(rt.block_on(pair(&state, "abc", "12345", None, "self")).is_err());
        assert!(rt.block_on(pair(&state, "abc", "abcdef", None, "self")).is_err());
        assert!(rt.block_on(remove(&state, "  ")).is_err());
    }
}
