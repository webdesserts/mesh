//! Daemon lifecycle for `Mesh.app`.
//!
//! Two modes:
//! - **Owned** — `Mesh.app` starts `MeshDaemon` in-process, serves the TCP API
//!   (`127.0.0.1:4620`) and the `register.sock` UDS, and shuts both down on quit.
//! - **Attached** — an external `webdesserts-mesh serve` already answers
//!   `GET /status` on `listen_addr`; `Mesh.app` only drives it over HTTP.

use crate::api_client;
use anyhow::{Context, Result};
use axum::Router;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use webdesserts_mesh::MeshDaemon;
use webdesserts_mesh::api;
use webdesserts_mesh::config::{MeshConfig, MeshPaths};

/// How this app relates to the running daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMode {
    Owned,
    Attached,
}

impl HostMode {
    pub fn label(self) -> &'static str {
        match self {
            HostMode::Owned => "in-process",
            HostMode::Attached => "external daemon",
        }
    }
}

/// Owns the daemon (owned mode) and the shutdown channel for its server tasks.
pub struct DaemonHost {
    pub mode: HostMode,
    pub paths: MeshPaths,
    daemon: Arc<Mutex<Option<Arc<MeshDaemon>>>>,
    shutdown: watch::Sender<bool>,
}

impl DaemonHost {
    /// Attach to an existing daemon if `listen_addr` already answers, otherwise
    /// start one in-process and serve its API.
    pub async fn start(paths: MeshPaths, cfg: MeshConfig, extra: Router) -> Result<Self> {
        let (shutdown, rx) = watch::channel(false);
        let base = api_client::base_url(&cfg.listen_addr);

        if api_client::probe(&base).await {
            tracing::info!(base = %base, "attached to existing mesh daemon");
            return Ok(Self {
                mode: HostMode::Attached,
                paths,
                daemon: Arc::new(Mutex::new(None)),
                shutdown,
            });
        }

        let daemon = Arc::new(
            MeshDaemon::start(paths.clone(), cfg.clone())
                .await
                .context("start mesh daemon")?,
        );
        daemon.start_poke_gossip().await.context("start poke gossip")?;
        let state = daemon.api_state();

        // TCP API (`127.0.0.1:4620`): mutating routes require the admin token.
        let tcp_state = state.clone();
        let listen_addr = cfg.listen_addr.clone();
        let mut tcp_rx = rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                result = api::serve_with_extra(tcp_state, &listen_addr, extra) => {
                    if let Err(e) = result {
                        tracing::warn!(error = %e, "mesh TCP API stopped");
                    }
                }
                _ = tcp_rx.changed() => {}
            }
        });

        // Local app registration socket (`0600`, pre-authenticated by OS perms).
        let uds_state = state.clone();
        let register_sock = paths.register_sock.clone();
        let mut uds_rx = rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                result = api::serve_uds(uds_state, register_sock) => {
                    if let Err(e) = result {
                        tracing::warn!(error = %e, "mesh UDS API stopped");
                    }
                }
                _ = uds_rx.changed() => {}
            }
        });

        tracing::info!(
            listen = %cfg.listen_addr,
            peer = %daemon.self_id,
            "mesh daemon up in-process"
        );

        Ok(Self {
            mode: HostMode::Owned,
            paths,
            daemon: Arc::new(Mutex::new(Some(daemon))),
            shutdown,
        })
    }

    /// Signal the server tasks, remove `register.sock`, and shut the daemon down.
    pub async fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        if self.mode != HostMode::Owned {
            return;
        }
        let _ = std::fs::remove_file(&self.paths.register_sock);
        let taken = {
            let mut guard = self.daemon.lock().await;
            guard.take()
        };
        let Some(daemon) = taken else { return };
        match Arc::try_unwrap(daemon) {
            Ok(daemon) => {
                if let Err(e) = daemon.shutdown().await {
                    tracing::warn!(error = %e, "mesh daemon shutdown failed");
                }
            }
            Err(_) => tracing::warn!("mesh daemon still shared; skipping shutdown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_mode_labels() {
        assert_eq!(HostMode::Owned.label(), "in-process");
        assert_eq!(HostMode::Attached.label(), "external daemon");
    }
}
