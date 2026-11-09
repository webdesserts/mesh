//! Mesh poke: a tiny gossip broadcast that wakes a peer long-poll.
//!
//! `seq` is **receiver-local** and monotonic: the sender puts a `nonce` on the
//! wire (so iroh-gossip PlumTree content-dedup cannot drop a repeated cursor),
//! and each receiver allocates its own `seq` on receipt. A sender-allocated
//! `seq` breaks multi-peer polling: if umbra sends 1..5 and charon sends its
//! first poke as 1, a receiver polling `since=5` drops charon forever.
//!
//! `from_device` is resolved from the **receiver'"'"'s** allowlist by
//! `sender_peer_id`; it is never taken from the sender-claimed name.
//!
//! `epoch` is a random per-boot value: a client polling with a `since` from
//! before a daemon restart sees `truncated: true` and an `effective_since` of
//! 0, so post-restart pokes are delivered instead of silently filtered out.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use p2p_core::gossip::Topic;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// Gossip topic for mesh pokes (blake3 of the domain string, 32 bytes).
pub fn poke_topic() -> Topic {
    Topic::from_bytes(*blake3::hash(b"webdesserts/mesh/poke/1").as_bytes())
}

/// Wire payload broadcast on the poke topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshPokeWire {
    pub app_id: String,
    #[serde(default)]
    pub topic: String,
    pub cursor: String,
    pub sender_peer_id: String,
    #[serde(default)]
    pub timestamp_ms: u64,
    /// Random per-send value: iroh-gossip dedups by content, so two pokes with
    /// the same cursor would otherwise be dropped as duplicates.
    #[serde(default)]
    pub nonce: u64,
}

/// A poke as stored on the receiver: receiver-local `seq` plus a resolved
/// `from_device` (from the receiver'"'"'s allowlist, `None` when unknown).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPoke {
    pub seq: u64,
    pub app_id: String,
    pub topic: String,
    pub cursor: String,
    pub sender_peer_id: String,
    pub from_device: Option<String>,
    pub timestamp_ms: u64,
}

/// Bounded in-memory inbox of received pokes plus a wake signal.
///
/// Uses `tokio::sync::watch<u64>` (the latest receiver seq) rather than
/// `Notify`: `notify_one` wakes only ONE long-poller per poke, so a second
/// concurrent `GET /pokes` would sit until `timeout_ms`. `watch` gives every
/// subscriber every bump and loses nothing.
#[derive(Debug)]
pub struct PokeInbox {
    inner: std::sync::Mutex<VecDeque<StoredPoke>>,
    next_seq: AtomicU64,
    tx: watch::Sender<u64>,
    cap: usize,
    /// Random per-boot epoch: lets a client detect a daemon restart.
    epoch: u64,
    /// Highest `seq` evicted from the ring buffer (0 = nothing evicted yet).
    evicted_seq: AtomicU64,
}

impl Default for PokeInbox {
    fn default() -> Self {
        Self::new(512)
    }
}

impl PokeInbox {
    pub fn new(cap: usize) -> Self {
        Self::with_epoch(cap, rand::random::<u64>().max(1))
    }

    /// Build an inbox with an explicit epoch (tests use a fixed value).
    pub fn with_epoch(cap: usize, epoch: u64) -> Self {
        let (tx, _rx) = watch::channel(0u64);
        Self {
            inner: std::sync::Mutex::new(VecDeque::new()),
            next_seq: AtomicU64::new(1),
            tx,
            cap,
            epoch,
            evicted_seq: AtomicU64::new(0),
        }
    }

    /// Subscribe to the receiver-local seq. Every subscriber sees every bump.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.tx.subscribe()
    }

    /// Store a received poke, allocating the receiver-local `seq`.
    ///
    /// `from_device` must come from the receiver'"'"'s allowlist lookup; pass
    /// `None` when the sender is not paired (never fall back to a claimed name).
    pub fn push(&self, wire: MeshPokeWire, from_device: Option<String>) -> u64 {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let stored = StoredPoke {
            seq,
            app_id: wire.app_id,
            topic: wire.topic,
            cursor: wire.cursor,
            sender_peer_id: wire.sender_peer_id,
            from_device,
            timestamp_ms: wire.timestamp_ms,
        };
        let mut q = self.inner.lock().expect("poke inbox poisoned");
        if q.len() >= self.cap {
            if let Some(evicted) = q.pop_front() {
                self.evicted_seq.store(evicted.seq, Ordering::SeqCst);
            }
        }
        q.push_back(stored);
        drop(q);
        let _ = self.tx.send(seq);
        seq
    }

    /// Pokes with `seq > since`, optionally filtered by app id.
    pub fn since(&self, since: u64, app_id: Option<&str>) -> Vec<StoredPoke> {
        let q = self.inner.lock().expect("poke inbox poisoned");
        q.iter()
            .filter(|w| w.seq > since)
            .filter(|w| app_id.is_none_or(|a| w.app_id == a))
            .cloned()
            .collect()
    }

    /// Read pokes with restart/eviction recovery.
    ///
    /// Returns `(pokes, truncated, effective_since)`. `truncated` is `true` when
    /// the caller'"'"'s `epoch` does not match this inbox'"'"'s epoch (daemon restart),
    /// when `since` is ahead of the latest seq, or when `since` fell behind the
    /// ring buffer. In every truncated case `effective_since` is 0, so the
    /// caller sees every buffered poke instead of silently filtering them out.
    pub fn read_since(
        &self,
        since: u64,
        req_epoch: Option<u64>,
        app_id: Option<&str>,
    ) -> (Vec<StoredPoke>, bool, u64) {
        let latest = self.latest_seq();
        let evicted = self.evicted_seq.load(Ordering::SeqCst);
        let truncated = req_epoch.is_some_and(|e| e != self.epoch)
            || since > latest
            || (since > 0 && since <= evicted);
        let effective_since = if truncated { 0 } else { since };
        let q = self.inner.lock().expect("poke inbox poisoned");
        let pokes = q
            .iter()
            .filter(|w| w.seq > effective_since)
            .filter(|w| app_id.is_none_or(|a| w.app_id == a))
            .cloned()
            .collect();
        (pokes, truncated, effective_since)
    }

    /// Latest receiver-local seq.
    pub fn latest_seq(&self) -> u64 {
        *self.tx.borrow()
    }

    /// Random per-boot epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Shared handle used by the API and the gossip loop.
pub type SharedPokeInbox = Arc<PokeInbox>;
