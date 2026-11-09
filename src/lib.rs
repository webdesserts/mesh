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
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use p2p_core::PeerId;
use p2p_core::allowlist::{AllowlistError, AllowlistStorage, FileAllowlistStorage};
use p2p_core::pairing::PairingChallenge;
use p2p_core::pairing_handler::{PairingApproval, PairingEvent};
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

/// How long a code armed by `POST /pair/code` stays valid.
pub const PAIRING_CODE_TTL: Duration = Duration::from_secs(300);

/// A single-use pairing code armed on the acceptor (`POST /pair/code`).
///
/// The first non-revoked inbound `PairingEvent::InboundRequest` consumes it
/// (`take()`), so an attacker minting fresh `PeerId`s over the public relay
/// cannot brute-force the code across multiple connections.
#[derive(Debug, Clone)]
pub struct PendingPairing {
    pub code: String,
    pub expires_at: Instant,
}

/// Add or update a peer, keeping device names unique (case-insensitive).
///
/// `resolve_target` matches `device_name` case-insensitively and returns the
/// first match, so two active peers sharing a name would be ambiguous. When a
/// different active peer already holds `desired_name`, suffix `-<8hex>`.
///
/// A tombstoned peer (`removed = true`) is refused with
/// `AllowlistError::PeerRevoked` before anything is written.
pub async fn add_or_update_peer_unique(
    allowlist: &Arc<FileAllowlistStorage>,
    peer_id: PeerId,
    desired_name: &str,
) -> Result<String, AllowlistError> {
    let peers = allowlist.list_peers().await?;
    if peers.iter().any(|p| p.node_id == peer_id && p.removed) {
        return Err(AllowlistError::PeerRevoked(peer_id));
    }
    let desired = desired_name.trim();
    let desired = if desired.is_empty() { "peer" } else { desired };
    let clash = peers.iter().any(|p| {
        p.node_id != peer_id && !p.removed && p.device_name.eq_ignore_ascii_case(desired)
    });
    let final_name = if clash {
        let hex = peer_id.to_string();
        format!("{desired}-{}", &hex[..8.min(hex.len())])
    } else {
        desired.to_string()
    };
    allowlist.add_peer(peer_id, final_name.clone()).await?;
    Ok(final_name)
}

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
    /// Public relays this node knows. Seeded into iroh'"'"'s `MemoryLookup` for
    /// every paired peer so off-LAN `PeerId`s resolve without mDNS.
    pub relays: Vec<RelayAddr>,
    /// Single-use pairing code armed by `POST /pair/code`.
    pub pending_pairing: Arc<Mutex<Option<PendingPairing>>>,
    /// Loopback health URL of `NotesSync.app`, probed by `GET /status`.
    pub notes_health_url: String,
    /// Whether this daemon started an embedded relay (`relay_listen = true`).
    pub relay_listen: bool,
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

        let mut node = P2pNode::builder(identity.secret_key_bytes(), &relays, allowlist.clone())
            .mdns_service_name(MDNS_SERVICE_NAME)
            .with_protocol(HTTP_PROXY_ALPN, handler)
            .build()
            .await
            .context("build p2p node")?;

        // A.1: seed relay hints for every existing non-removed peer so iroh'"'"'s
        // `MemoryLookup` resolves off-LAN `PeerId`s without mDNS.
        for peer in allowlist.list_peers().await.unwrap_or_default() {
            if !peer.removed && peer.node_id != self_id {
                for relay in &relays {
                    node.add_peer_relay(peer.node_id, relay);
                }
            }
        }

        // A.2: take the inbound pairing receiver out of the node so the daemon
        // can drive it (zero `p2p-core` changes; the field is `pub`).
        let (_dummy_tx, dummy_rx) = tokio::sync::mpsc::unbounded_channel::<PairingEvent>();
        let mut inbound_pairing_rx = std::mem::replace(&mut node.inbound_pairing_rx, dummy_rx);

        let node = Arc::new(node);
        let pending_pairing: Arc<Mutex<Option<PendingPairing>>> = Arc::new(Mutex::new(None));
        let gossip: Arc<Mutex<Option<GossipHandle>>> = Arc::new(Mutex::new(None));
        let device_name = cfg.device_name.clone();
        let notes_health_url = cfg.notes_health_url.clone();
        let relay_listen = cfg.relay_listen;

        // A.2: drive inbound pairing requests. The code is single-use and is
        // consumed only by a non-revoked peer, so it cannot be brute-forced
        // across fresh `PeerId`s over the public relay.
        {
            let node = node.clone();
            let allowlist = allowlist.clone();
            let gossip = gossip.clone();
            let pending_pairing = pending_pairing.clone();
            let relays = relays.clone();
            let device_name = device_name.clone();
            tokio::spawn(async move {
                while let Some(ev) = inbound_pairing_rx.recv().await {
                    match ev {
                        PairingEvent::InboundRequest(exchange) => {
                            let peer_id = exchange.remote_id;
                            // S2: reject a revoked peer before consuming the code.
                            let peers = allowlist.list_peers().await.unwrap_or_default();
                            if peers.iter().any(|p| p.node_id == peer_id && p.removed) {
                                tracing::warn!(peer = %peer_id, "rejecting inbound pairing from revoked peer");
                                drop(exchange.reply_tx);
                                continue;
                            }
                            // B2: consume the single-use code on the first
                            // non-revoked inbound request.
                            let pending = pending_pairing.lock().await.take();
                            let Some(pending) = pending else {
                                tracing::warn!(peer = %peer_id, "no armed pairing code; rejecting inbound pairing");
                                drop(exchange.reply_tx);
                                continue;
                            };
                            if Instant::now() >= pending.expires_at {
                                tracing::warn!(peer = %peer_id, "armed pairing code expired; rejecting inbound pairing");
                                drop(exchange.reply_tx);
                                continue;
                            }
                            let mesh_members: Vec<PeerId> = peers
                                .iter()
                                .filter(|p| !p.removed)
                                .map(|p| p.node_id)
                                .collect();
                            let approval = PairingApproval {
                                code: pending.code,
                                challenge: PairingChallenge {
                                    node_id: self_id,
                                    device_name: device_name.clone(),
                                },
                                vault_topic: *poke_topic().as_bytes(),
                                relay_urls: relays.iter().map(|r| r.as_str()).collect(),
                                mesh_members,
                            };
                            let _ = exchange.reply_tx.send(approval);
                        }
                        PairingEvent::PairingCompleted { peer_id, device_name: peer_name } => {
                            match add_or_update_peer_unique(&allowlist, peer_id, &peer_name).await {
                                Ok(name) => tracing::info!(peer = %peer_id, name = %name, "inbound mesh pairing completed"),
                                Err(e) => {
                                    tracing::warn!(peer = %peer_id, error = %e, "persist inbound paired peer failed");
                                    continue;
                                }
                            }
                            for relay in &relays {
                                node.add_peer_relay(peer_id, relay);
                            }
                            let guard = gossip.lock().await;
                            if let Some(h) = guard.as_ref() {
                                if let Err(e) = h.rejoin_peers(vec![peer_id]).await {
                                    tracing::warn!(peer = %peer_id, error = %e, "rejoin_peers after inbound pair failed");
                                }
                            }
                        }
                        PairingEvent::PairingFailed { peer_id, reason } => {
                            tracing::warn!(%peer_id, %reason, "inbound mesh pairing failed");
                        }
                    }
                }
            });
        }

        Ok(Self {
            node,
            allowlist,
            inbox: Arc::new(PokeInbox::new(512)),
            gossip,
            pool: new_pool(),
            device_name: cfg.device_name,
            self_id,
            apps,
            paths,
            relays,
            pending_pairing,
            notes_health_url,
            relay_listen,
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
            relays: self.relays.clone(),
            pending_pairing: self.pending_pairing.clone(),
            notes_health_url: self.notes_health_url.clone(),
            relay_listen: self.relay_listen,
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
