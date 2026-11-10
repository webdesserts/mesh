//! Tauri managed state shared by the tray, menu events and commands.

use crate::api_client::Client;
use crate::daemon_host::DaemonHost;
use std::sync::Arc;
use tokio::sync::Mutex;
use webdesserts_mesh::config::{MeshConfig, MeshPaths};

pub struct AppState {
    /// Loopback HTTP client bound to the daemon base URL + admin token.
    pub client: Client,
    /// The daemon host, if this app owns or attached to one.
    pub host: Mutex<Option<Arc<DaemonHost>>>,
    pub paths: MeshPaths,
    /// Live config (mirrors `config.toml`; updated by the relay toggle).
    pub cfg: Mutex<MeshConfig>,
    /// Last rendered tray signature, so the menu is only rebuilt on change.
    pub last_menu: Mutex<String>,
}
