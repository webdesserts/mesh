//! `webdesserts-mesh`: a mesh daemon that proxies loopback HTTP requests
//! between paired devices and broadcasts pokes over gossip.
//!
//! Built on `p2p-core` v0.1.2. The proxy ALPN is registered **ungated**
//! (`with_protocol`) on purpose: `MeshHttpProxyHandler` performs its own
//! per-bi-stream allowlist re-check (C1(a)), which is stricter than
//! `p2p-core`'"'"'s once-per-connection `AllowlistProtocolHandler`.

pub mod api;
pub mod config;
pub mod poke;
pub mod proxy;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use p2p_core::PeerId;
use p2p_core::allowlist::{AllowlistStorage, FileAllowlistStorage};
use p2p_core::daemon_lock::DaemonLock;
use p2p_core::gossip::{GossipEvent, GossipHandle};
use p2p_core::identity::IdentityKey;
use p2p_core::node::P2pNode;
use p2p_core::relay::EmbeddedRelay;
use p2p_core::relay_addr::RelayAddr;
use tokio::sync::Mutex;

use crate::config::{AppTargetConfig, MeshConfig, MeshPaths};
use crate::poke::{MeshPokeWire, PokeInbox, SharedPokeInbox, poke_topic};
use crate::proxy::{ConnPool, HTTP_PROXY_ALPN, MeshHttpProxyHandler, new_pool};

/// mDNS service name. `p2p-core` caps this at 15 bytes and rejects anything
/// outside `[a-z0-9-]`; an invalid name silently loses LAN discovery, so keep
/// it short and valid.
pub const MDNS_SERVICE_NAME: &str = "wd-mesh";

/// A running mesh daemon.
pub struct MeshDaemon {
    pub node: Arc<P2pNode>,
    pub allowlist: Arc<FileAllowlistStorage>,
    pub inbox: SharedPokeInbox,
    pub gossip: Arc<Mutex<Option<GossipHandle>>>,
    pub pool: ConnPool,
    pub device_name: String,
    pub self_id: PeerId,
    pub apps: Arc<HashMap<String, AppTargetConfig>>,
    pub paths: MeshPaths,
    /// Embedded relay, held for the Phase 3 cutover. `None` unless
    /// `relay_listen = true` (default false: NotesSync owns `0.0.0.0:3340`).
    _relay: Option<EmbeddedRelay>,
    _lock: DaemonLock,
}

impl MeshDaemon {
    /// Acquire the daemon lock, load identity, and build the node.
    pub async fn start(paths: MeshPaths, cfg: MeshConfig) -> Result<Self> {
        cfg.validate()?;
        paths.ensure_dir()?;

        let lock = DaemonLock::acquire_at(&paths.lock)
            .map_err(|e| anyhow::anyhow!("acquire mesh lock: {e}"))?;

        let identity = IdentityKey::load_or_generate_at(&paths.key)
            .await
            .context("load or generate mesh identity")?;
        let self_id = identity.peer_id();

        let allowlist = Arc::new(FileAllowlistStorage::at_path(&paths.allowlist));

        let relays: Vec<RelayAddr> = cfg
            .known_public_relays
            .iter()
            .filter_map(|s| RelayAddr::parse(s).ok())
            .collect();

        let apps: Arc<HashMap<String, AppTargetConfig>> =
            Arc::new(cfg.apps.clone().into_iter().collect());

        // Optional embedded relay. Default off: on umbra, NotesSync already
        // holds 0.0.0.0:3340, so a default-on relay would fail to bind.
        let relay = if cfg.relay_listen {
            let bind = cfg
                .relay_bind
                .clone()
                .unwrap_or_else(|| crate::config::DEFAULT_RELAY_BIND.to_string());
            let addr: SocketAddr = bind
                .parse()
                .with_context(|| format!("parse relay_bind {bind:?}"))?;
            Some(
                EmbeddedRelay::start(addr)
                    .await
                    .context("start embedded relay")?,
            )
        } else {
            None
        };

        let handler = MeshHttpProxyHandler::new(allowlist.clone(), apps.clone());

        let node = P2pNode::builder(identity.secret_key_bytes(), &relays, allowlist.clone())
            .mdns_service_name(MDNS_SERVICE_NAME)
            .with_protocol(HTTP_PROXY_ALPN, handler)
            .build()
            .await
            .context("build p2p node")?;

        Ok(Self {
            node: Arc::new(node),
            allowlist,
            inbox: Arc::new(PokeInbox::new(512)),
            gossip: Arc::new(Mutex::new(None)),
            pool: new_pool(),
            device_name: cfg.device_name,
            self_id,
            apps,
            paths,
            _relay: relay,
            _lock: lock,
        })
    }

    /// Join the poke gossip topic and pump received pokes into the inbox.
    ///
    /// `from_device` is resolved from the **receiver'"'"'s** allowlist by
    /// `sender_peer_id`; a sender-claimed name is never trusted, and an
    /// unknown sender yields `None`.
    pub async fn start_poke_gossip(&self) -> Result<()> {
        let bootstrap: Vec<PeerId> = self
            .allowlist
            .list_peers()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|p| !p.removed)
            .map(|p| p.node_id)
            .collect();

        let mut sub = self
            .node
            .subscribe(poke_topic(), bootstrap)
            .await
            .context("subscribe poke topic")?;
        let handle = sub.handle();
        *self.gossip.lock().await = Some(handle);

        let inbox = self.inbox.clone();
        let allowlist = self.allowlist.clone();
        tokio::spawn(async move {
            while let Some(ev) = sub.recv().await {
                match ev {
                    GossipEvent::Data { bytes, .. } => {
                        let Ok(wire) = serde_json::from_slice::<MeshPokeWire>(&bytes) else {
                            continue;
                        };
                        let from_device = match wire.sender_peer_id.parse::<PeerId>() {
                            Ok(peer) => allowlist
                                .list_peers()
                                .await
                                .ok()
                                .and_then(|peers| {
                                    peers
                                        .into_iter()
                                        .find(|p| p.node_id == peer && !p.removed)
                                        .map(|p| p.device_name)
                                }),
                            Err(_) => None,
                        };
                        inbox.push(wire, from_device);
                    }
                    GossipEvent::NeighborUp(_) | GossipEvent::NeighborDown(_) => {}
                    GossipEvent::Lagged => {}
                }
            }
        });
        Ok(())
    }

    /// Build the API state for the loopback server. The gossip handle and the
    /// connection pool are **shared** with the daemon, so `/poke` broadcasts on
    /// the live subscription and proxied requests reuse one QUIC handshake.
    pub fn api_state(self: &Arc<Self>) -> Arc<api::ApiState> {
        Arc::new(api::ApiState {
            node: self.node.clone(),
            allowlist: self.allowlist.clone(),
            apps: self.apps.clone(),
            inbox: self.inbox.clone(),
            gossip: self.gossip.clone(),
            pool: self.pool.clone(),
            device_name: self.device_name.clone(),
            self_id: self.self_id,
        })
    }

    pub async fn shutdown(self) -> Result<()> {
        if let Some(relay) = self._relay {
            relay.shutdown().await;
        }
        match Arc::try_unwrap(self.node) {
            Ok(node) => node.shutdown().await.context("shutdown node")?,
            Err(_) => tracing::warn!("node still shared; skipping shutdown"),
        }
        Ok(())
    }
}
