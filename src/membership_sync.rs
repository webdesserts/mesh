//! `ALPN_MEMBERSHIP`: two-sided pairing membership handshake and anti-entropy.
//!
//! The acceptor never writes `allowlist.json` from a pairing event. It records an
//! in-memory pending grant, admits the joiner over `ALPN_MEMBERSHIP`, and only
//! then merges a signed `Add` into `membership.json` (whose projection is the
//! sole writer of `allowlist.json`).

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use p2p_core::PeerId;
use p2p_core::membership::{
    MembershipLog, Relationship, SignedMembershipEntry,
};
use p2p_core::protocol::{AcceptError, ProtocolHandler};
use p2p_core::streams::{read_length_prefixed, write_length_prefixed};
use bytes::Bytes;
use p2p_core::gossip::GossipHandle;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::membership_store::MembershipStore;
use crate::poke::MeshPokeWire;
use crate::proxy::{NOT_IN_ALLOWLIST_CODE, NOT_IN_ALLOWLIST_REASON, peer_id_of};

/// ALPN for the membership sync protocol.
pub const ALPN_MEMBERSHIP: &[u8] = b"webdesserts/mesh/membership/1";

/// Max frame size for a membership sync message (a full log can be large).
pub const MAX_MEMBERSHIP_FRAME: usize = 4 * 1024 * 1024;

/// Request sent over `ALPN_MEMBERSHIP`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MembershipWireReq {
    /// Two-sided pairing handshake (S1b/S1c/S1d).
    PairSync {
        initiator_log: MembershipLog,
        initiator_device_name: String,
        /// Present when the initiator is established: a signed `Add` for the
        /// acceptor, so the acceptor can adopt the initiator'"'"'s mesh.
        #[serde(default)]
        candidate_acceptor_add: Option<SignedMembershipEntry>,
    },
    /// Pull every entry the caller is missing.
    AntiEntropy {
        mesh_id: String,
        known_entry_ids: Vec<String>,
    },
}

/// Response to a `MembershipWireReq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MembershipWireResp {
    PairSync { canonical_log: MembershipLog },
    AntiEntropy {
        mesh_id: String,
        missing_entries: Vec<SignedMembershipEntry>,
    },
    Error { code: u16, message: String },
}

/// Compact gossip frame: pokes, membership entries, and anti-entropy hints.
///
/// Kept small (well under iroh-gossip'"'"'s 4 KiB default `max_message_size`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MeshWireMessage {
    Poke(MeshPokeWire),
    Membership(SignedMembershipEntry),
    AntiEntropy { mesh_id: String, heads: Vec<String> },
}

/// Server side of `ALPN_MEMBERSHIP`.
pub struct MembershipSyncHandler {
    store: Arc<MembershipStore>,
    gossip: Arc<Mutex<Option<GossipHandle>>>,
}

// `GossipHandle` is not `Debug`; render only the store so logs stay useful.
impl std::fmt::Debug for MembershipSyncHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipSyncHandler")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl MembershipSyncHandler {
    pub fn new(store: Arc<MembershipStore>, gossip: Arc<Mutex<Option<GossipHandle>>>) -> Self {
        Self { store, gossip }
    }

    /// Announce our current heads so neighbors already connected pull the
    /// entries a fresh pairing just added (`NeighborUp` fired long ago).
    async fn broadcast_heads(&self) {
        let log = self.store.log_snapshot().await;
        let wire = MeshWireMessage::AntiEntropy {
            mesh_id: log.mesh_id.clone(),
            heads: log.evaluate().heads,
        };
        let bytes = match serde_json::to_vec(&wire) {
            Ok(b) => b,
            Err(_) => return,
        };
        let guard = self.gossip.lock().await;
        if let Some(h) = guard.as_ref() {
            if let Err(e) = h.broadcast(Bytes::from(bytes)).await {
                tracing::warn!(error = %e, "membership anti-entropy broadcast failed");
            }
        }
    }

    async fn write_resp(&self, send: &mut SendStream, resp: &MembershipWireResp) -> Result<()> {
        let bytes = serde_json::to_vec(resp).context("serialize membership response")?;
        write_length_prefixed(send, &bytes)
            .await
            .context("write membership response")?;
        let _ = send.finish();
        Ok(())
    }

    async fn serve(&self, mut send: SendStream, mut recv: RecvStream, peer: PeerId) -> Result<()> {
        let frame = read_length_prefixed(&mut recv)
            .await
            .context("read membership request")?;
        if frame.len() > MAX_MEMBERSHIP_FRAME {
            bail!("membership request exceeds {MAX_MEMBERSHIP_FRAME} bytes");
        }
        let req: MembershipWireReq =
            serde_json::from_slice(&frame).context("parse membership request")?;
        let resp = match req {
            MembershipWireReq::PairSync {
                initiator_log,
                initiator_device_name,
                candidate_acceptor_add,
            } => self
                .pair_sync(peer, initiator_log, initiator_device_name, candidate_acceptor_add)
                .await,
            MembershipWireReq::AntiEntropy {
                mesh_id,
                known_entry_ids,
            } => self.anti_entropy(mesh_id, known_entry_ids).await,
        };
        self.write_resp(&mut send, &resp).await
    }

    /// Anti-entropy pull: return every entry the caller does not know.
    async fn anti_entropy(
        &self,
        mesh_id: String,
        known_entry_ids: Vec<String>,
    ) -> MembershipWireResp {
        let log = self.store.log_snapshot().await;
        if mesh_id != log.mesh_id {
            return MembershipWireResp::Error {
                code: 409,
                message: "mesh_id mismatch".to_string(),
            };
        }
        let missing: Vec<SignedMembershipEntry> = log
            .entries
            .values()
            .filter(|e| !known_entry_ids.contains(&e.entry_id))
            .cloned()
            .collect();
        MembershipWireResp::AntiEntropy {
            mesh_id: log.mesh_id.clone(),
            missing_entries: missing,
        }
    }

    /// The 4-case rule table for `PairSync` (S1b/S1c/S1d).
    async fn pair_sync(
        &self,
        initiator_id: PeerId,
        initiator_log: MembershipLog,
        initiator_device_name: String,
        candidate_acceptor_add: Option<SignedMembershipEntry>,
    ) -> MembershipWireResp {
        let acceptor_id = self.store.self_id();
        let acceptor_log = self.store.log_snapshot().await;
        let acceptor_solo = acceptor_log.entries.len() == 1;
        let initiator_solo = initiator_log.entries.len() == 1;
        let same_mesh = acceptor_log.mesh_id == initiator_log.mesh_id;

        // Sticky revocation (S1c): a revoked key must rotate before re-pairing.
        let acceptor_eval = acceptor_log.evaluate();
        // Sticky revocation also applies to the initiator log: a solo acceptor
        // (Case 2) must refuse a peer its own log already revoked.
        let initiator_eval = initiator_log.evaluate();
        if acceptor_eval.revoked.contains_key(&initiator_id)
            || acceptor_eval.revoked.contains_key(&acceptor_id)
            || initiator_eval.revoked.contains_key(&initiator_id)
            || initiator_eval.revoked.contains_key(&acceptor_id)
        {
            return MembershipWireResp::Error {
                code: 409,
                message: "peer key is revoked in membership log; rotate key first".to_string(),
            };
        }

        // Case 4: two established meshes with different ids cannot merge.
        if !acceptor_solo && !initiator_solo && !same_mesh {
            return MembershipWireResp::Error {
                code: 409,
                message: "cannot merge two distinct multi-device meshes; reset solo device first"
                    .to_string(),
            };
        }

        // Case 2: the initiator is established and we are solo -> adopt its mesh.
        if !initiator_solo && acceptor_solo {
            if let Err(e) = self.verify_log(&initiator_log) {
                return MembershipWireResp::Error {
                    code: 400,
                    message: e.to_string(),
                };
            }
            let mut adopted = initiator_log;
            if let Some(add) = candidate_acceptor_add {
                if !add.verify() || add.mesh_id() != adopted.mesh_id {
                    return MembershipWireResp::Error {
                        code: 400,
                        message: "candidate acceptor add is invalid".to_string(),
                    };
                }
                if let Err(e) = adopted.merge_entries(std::slice::from_ref(&add)) {
                    return MembershipWireResp::Error {
                        code: 400,
                        message: e.to_string(),
                    };
                }
            }
            if !adopted.evaluate().active.contains_key(&acceptor_id) {
                return MembershipWireResp::Error {
                    code: 409,
                    message: "acceptor is not active in the adopted log".to_string(),
                };
            }
            if let Err(e) = self.store.adopt_log(adopted.clone()).await {
                return MembershipWireResp::Error {
                    code: 500,
                    message: e.to_string(),
                };
            }
            self.store.clear_pending(&initiator_id).await;
            self.broadcast_heads().await;
            return MembershipWireResp::PairSync {
                canonical_log: adopted,
            };
        }

        // Case 3: same mesh_id -> merge the initiator'"'"'s entries.
        if same_mesh && !acceptor_solo {
            if let Err(e) = self.verify_log(&initiator_log) {
                return MembershipWireResp::Error {
                    code: 400,
                    message: e.to_string(),
                };
            }
            let incoming: Vec<SignedMembershipEntry> =
                initiator_log.entries.values().cloned().collect();
            if let Err(e) = self.store.merge_entries(&incoming).await {
                return MembershipWireResp::Error {
                    code: 400,
                    message: e.to_string(),
                };
            }
            let eval = self.store.evaluate().await;
            if eval.revoked.contains_key(&initiator_id) {
                return MembershipWireResp::Error {
                    code: 409,
                    message: "peer key is revoked in membership log; rotate key first".to_string(),
                };
            }
            if !eval.active.contains_key(&initiator_id) {
                match self
                    .store
                    .sign_add(initiator_id, &initiator_device_name, Relationship::SelfDevice)
                    .await
                {
                    Ok(entry) => {
                        if let Err(e) = self.store.append_entry(entry).await {
                            return MembershipWireResp::Error {
                                code: 500,
                                message: e.to_string(),
                            };
                        }
                    }
                    Err(e) => {
                        return MembershipWireResp::Error {
                            code: 500,
                            message: e.to_string(),
                        };
                    }
                }
            }
            self.store.clear_pending(&initiator_id).await;
            self.broadcast_heads().await;
            return MembershipWireResp::PairSync {
                canonical_log: self.store.log_snapshot().await,
            };
        }

        // Case 1: the acceptor'"'"'s mesh_id wins (established acceptor, or both solo).
        match self
            .store
            .sign_add(initiator_id, &initiator_device_name, Relationship::SelfDevice)
            .await
        {
            Ok(entry) => {
                if let Err(e) = self.store.append_entry(entry).await {
                    return MembershipWireResp::Error {
                        code: 500,
                        message: e.to_string(),
                    };
                }
            }
            Err(e) => {
                return MembershipWireResp::Error {
                    code: 500,
                    message: e.to_string(),
                };
            }
        }
        self.store.clear_pending(&initiator_id).await;
        self.broadcast_heads().await;
        MembershipWireResp::PairSync {
            canonical_log: self.store.log_snapshot().await,
        }
    }

    fn verify_log(&self, log: &MembershipLog) -> Result<()> {
        for entry in log.entries.values() {
            if !entry.verify() {
                bail!("membership log has an invalid entry {}", entry.entry_id);
            }
            if entry.mesh_id() != log.mesh_id {
                bail!("membership log entry has a mismatched mesh_id");
            }
        }
        Ok(())
    }
}

impl ProtocolHandler for MembershipSyncHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer = peer_id_of(&connection);
        // Admit an active member or a peer holding an unexpired pending grant
        // (the joiner'"'"'s immediate sync stream arrives before its Add lands).
        if !self.store.is_active_or_pending(&peer).await {
            connection.close(
                VarInt::from_u32(NOT_IN_ALLOWLIST_CODE),
                NOT_IN_ALLOWLIST_REASON,
            );
            return Ok(());
        }
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(bi) => bi,
                Err(_) => return Ok(()),
            };
            if !self.store.is_active_or_pending(&peer).await {
                connection.close(
                    VarInt::from_u32(NOT_IN_ALLOWLIST_CODE),
                    NOT_IN_ALLOWLIST_REASON,
                );
                return Ok(());
            }
            if let Err(e) = self.serve(send, recv, peer).await {
                tracing::warn!(error = %e, "membership sync bi-stream failed");
            }
        }
    }
}

/// Client side: pull every entry we are missing from `peer` over `ALPN_MEMBERSHIP`.
pub async fn pull_anti_entropy(
    node: &p2p_core::node::P2pNode,
    peer: PeerId,
    store: &MembershipStore,
) -> Result<Vec<PeerId>> {
    let log = store.log_snapshot().await;
    let req = MembershipWireReq::AntiEntropy {
        mesh_id: log.mesh_id.clone(),
        known_entry_ids: log.entries.keys().cloned().collect(),
    };
    let addr = p2p_core::peer_addr::PeerAddr::new(peer);
    let conn = node
        .connect(&addr, ALPN_MEMBERSHIP)
        .await
        .context("dial membership ALPN")?;
    let (mut send, mut recv) = conn.open_bi().await.context("open membership bi-stream")?;
    let bytes = serde_json::to_vec(&req).context("serialize anti-entropy request")?;
    write_length_prefixed(&mut send, &bytes)
        .await
        .context("write anti-entropy request")?;
    let _ = send.finish();
    let frame = read_length_prefixed(&mut recv)
        .await
        .context("read anti-entropy response")?;
    let resp: MembershipWireResp =
        serde_json::from_slice(&frame).context("parse anti-entropy response")?;
    match resp {
        MembershipWireResp::AntiEntropy { missing_entries, .. } => {
            // Merge what we pulled and hand back the peers this revoked so the
            // caller can run teardown (S3).
            let revoked = store.merge_entries(&missing_entries).await?;
            Ok(revoked)
        }
        MembershipWireResp::Error { code, message } => {
            bail!("anti-entropy failed ({code}): {message}")
        }
        MembershipWireResp::PairSync { .. } => bail!("unexpected PairSync response"),
    }
}

/// Initiator side of the two-sided pairing handshake (S1b).
///
/// Sends the local log (plus a candidate `Add` for the acceptor when this node
/// is already established), verifies the returned canonical log, and adopts it.
pub async fn pair_sync_initiator(
    node: &p2p_core::node::P2pNode,
    peer: PeerId,
    store: &MembershipStore,
    acceptor_device_name: &str,
) -> Result<MembershipLog> {
    let log = store.log_snapshot().await;
    let solo = log.entries.len() == 1;
    let candidate = if solo {
        None
    } else {
        Some(
            store
                .sign_add(peer, acceptor_device_name, Relationship::SelfDevice)
                .await?,
        )
    };
    let req = MembershipWireReq::PairSync {
        initiator_log: log,
        initiator_device_name: store.device_name().to_string(),
        candidate_acceptor_add: candidate,
    };
    let addr = p2p_core::peer_addr::PeerAddr::new(peer);
    let conn = node
        .connect(&addr, ALPN_MEMBERSHIP)
        .await
        .context("dial membership ALPN")?;
    let (mut send, mut recv) = conn.open_bi().await.context("open membership bi-stream")?;
    let bytes = serde_json::to_vec(&req).context("serialize pair sync request")?;
    write_length_prefixed(&mut send, &bytes)
        .await
        .context("write pair sync request")?;
    let _ = send.finish();
    let frame = read_length_prefixed(&mut recv)
        .await
        .context("read pair sync response")?;
    let resp: MembershipWireResp =
        serde_json::from_slice(&frame).context("parse pair sync response")?;
    match resp {
        MembershipWireResp::PairSync { canonical_log } => {
            for entry in canonical_log.entries.values() {
                if !entry.verify() {
                    bail!("canonical log has an invalid entry {}", entry.entry_id);
                }
                if entry.mesh_id() != canonical_log.mesh_id {
                    bail!("canonical log entry has a mismatched mesh_id");
                }
            }
            let eval = canonical_log.evaluate();
            let self_id = store.self_id();
            if !eval.active.contains_key(&self_id) || !eval.active.contains_key(&peer) {
                bail!("canonical log does not contain both peers as active");
            }
            store.adopt_log(canonical_log.clone()).await?;
            store.clear_pending(&peer).await;
            Ok(canonical_log)
        }
        MembershipWireResp::Error { code, message } => {
            bail!("pair sync failed ({code}): {message}")
        }
        MembershipWireResp::AntiEntropy { .. } => bail!("unexpected AntiEntropy response"),
    }
}
