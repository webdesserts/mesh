//! Native macOS menu-bar tray menu, refreshed every 3s.

use crate::api_client;
use crate::daemon_host::HostMode;
use crate::snapshot::{self, PeerRow, Snapshot};
use crate::state::AppState;
use tauri::menu::{CheckMenuItemBuilder, IsMenuItem, Menu, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_autostart::ManagerExt;

/// Tray id used by `app.tray_by_id`.
pub const TRAY_ID: &str = "main";

/// Create the tray icon with its initial menu.
pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let menu = menu_for(app, None, HostMode::Owned, None)?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(tauri::include_image!("icons/tray-icon.png"))
        .icon_as_template(true)
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| crate::menu_events::handle(app, event.id().as_ref()))
        .build(app)?;
    Ok(())
}

/// Poll the daemon and rebuild the menu when the rendered text changed.
pub async fn refresh(app: &AppHandle) {
    let state = app.state::<AppState>();
    let client = state.client.clone();
    let mode = {
        state
            .host
            .lock()
            .await
            .as_ref()
            .map(|h| h.mode)
            .unwrap_or(HostMode::Attached)
    };
    let relay_bind = { state.cfg.lock().await.relay_bind.clone() };
    let snap = snapshot::fetch(&client).await.ok();
    let sig = signature(snap.as_ref(), mode, relay_bind.as_deref());
    {
        let mut last = state.last_menu.lock().await;
        if *last == sig {
            return;
        }
        *last = sig;
    }
    match menu_for(app, snap.as_ref(), mode, relay_bind.as_deref()) {
        Ok(menu) => {
            if let Some(tray) = app.tray_by_id(TRAY_ID) {
                if let Err(e) = tray.set_menu(Some(menu)) {
                    tracing::warn!(error = %e, "set tray menu failed");
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "build tray menu failed"),
    }
}

fn relay_line(listen: bool, bind: Option<&str>) -> String {
    if listen {
        format!("Relay (:3340): Hosting ({})", bind.unwrap_or("0.0.0.0:3340"))
    } else {
        "Relay (:3340): Client only".to_string()
    }
}

fn notes_line(healthy: bool) -> String {
    if healthy {
        "NotesSync (:8082): Healthy".to_string()
    } else {
        "NotesSync (:8082): Offline".to_string()
    }
}

fn peer_line(p: &PeerRow) -> String {
    format!(
        "• {} ({}, {})",
        p.device_name,
        p.relationship,
        api_client::short_id(&p.peer_id)
    )
}

fn signature(snap: Option<&Snapshot>, mode: HostMode, relay_bind: Option<&str>) -> String {
    match snap {
        Some(s) => {
            let mut out = vec![
                s.status_line(mode.label()),
                format!("Node ID: {}", api_client::short_id(&s.peer_id())),
                relay_line(s.relay_listen(), relay_bind),
                notes_line(s.notes_healthy()),
            ];
            let peers = s.active_peers();
            if peers.is_empty() {
                out.push("• No paired devices".to_string());
            } else {
                for p in peers.iter().take(8) {
                    out.push(peer_line(p));
                }
            }
            out.join("\n")
        }
        None => "starting".to_string(),
    }
}

fn menu_for(
    app: &AppHandle,
    snap: Option<&Snapshot>,
    mode: HostMode,
    relay_bind: Option<&str>,
) -> tauri::Result<Menu<Wry>> {
    let (status_text, node_text, relay_text, notes_text, peers) = match snap {
        Some(s) => (
            s.status_line(mode.label()),
            format!("Node ID: {}", api_client::short_id(&s.peer_id())),
            relay_line(s.relay_listen(), relay_bind),
            notes_line(s.notes_healthy()),
            s.active_peers(),
        ),
        None => (
            "Mesh: starting…".to_string(),
            "Node ID: —".to_string(),
            "Relay (:3340): —".to_string(),
            "NotesSync (:8082): —".to_string(),
            Vec::new(),
        ),
    };

    let status_item = MenuItemBuilder::with_id("status", status_text).enabled(false).build(app)?;
    let node_item = MenuItemBuilder::with_id("node_id", node_text).enabled(false).build(app)?;
    let relay_item = MenuItemBuilder::with_id("relay_status", relay_text).enabled(false).build(app)?;
    let notes_item = MenuItemBuilder::with_id("notes_status", notes_text).enabled(false).build(app)?;

    let mut peer_items = Vec::new();
    if peers.is_empty() {
        peer_items.push(
            MenuItemBuilder::with_id("peers_empty", "• No paired devices")
                .enabled(false)
                .build(app)?,
        );
    } else {
        for (i, p) in peers.iter().take(8).enumerate() {
            peer_items.push(
                MenuItemBuilder::with_id(format!("peer-{i}"), peer_line(p))
                    .enabled(false)
                    .build(app)?,
            );
        }
    }

    let pair_item = MenuItemBuilder::with_id("pair", "Pair Device…").build(app)?;
    let copy_item = MenuItemBuilder::with_id("copy_node_id", "Copy Node ID").build(app)?;
    let toggle_item = CheckMenuItemBuilder::with_id("toggle_relay", "Host Relay (:3340)")
        .checked(relay_bind.is_some())
        .build(app)?;
    let restart_item = MenuItemBuilder::with_id("restart_daemon", "Restart Daemon").build(app)?;
    let updates_item = MenuItemBuilder::with_id("check_updates", "Check for Updates…").build(app)?;
    let autostart_on = app
        .autolaunch()
        .is_enabled()
        .unwrap_or(false);
    let autostart_item = CheckMenuItemBuilder::with_id("toggle_autostart", "Launch at Login")
        .checked(autostart_on)
        .build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit Mesh").build(app)?;

    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let sep3 = PredefinedMenuItem::separator(app)?;

    let mut refs: Vec<&dyn IsMenuItem<Wry>> = vec![&status_item, &node_item, &relay_item, &notes_item, &sep1];
    for p in &peer_items {
        refs.push(p);
    }
    refs.push(&sep2);
    refs.push(&pair_item);
    refs.push(&copy_item);
    refs.push(&toggle_item);
    refs.push(&sep3);
    refs.push(&restart_item);
    refs.push(&updates_item);
    refs.push(&autostart_item);
    refs.push(&quit_item);
    Menu::with_items(app, &refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_line_hosting_and_client() {
        assert_eq!(relay_line(true, Some("0.0.0.0:3340")), "Relay (:3340): Hosting (0.0.0.0:3340)");
        assert_eq!(relay_line(true, None), "Relay (:3340): Hosting (0.0.0.0:3340)");
        assert_eq!(relay_line(false, Some("0.0.0.0:3340")), "Relay (:3340): Client only");
    }

    #[test]
    fn notes_line_healthy_and_offline() {
        assert_eq!(notes_line(true), "NotesSync (:8082): Healthy");
        assert_eq!(notes_line(false), "NotesSync (:8082): Offline");
    }

    #[test]
    fn peer_line_formats_short_id() {
        let p = PeerRow {
            peer_id: "0123456789abcdef".to_string(),
            device_name: "rhea".to_string(),
            relationship: "friend".to_string(),
        };
        assert_eq!(peer_line(&p), "• rhea (friend, 0123456789ab…)");
    }
}
