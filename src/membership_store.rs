//! Signed membership log persistence and the single-writer allowlist projection.
//!
//! `membership.json` is the source of truth. `allowlist.json` is a *projection*
//! of `MembershipLog::evaluate()` and nothing else writes it, so a revoked peer
//! cannot be re-admitted by a stale merge.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use p2p_core::PeerId;
use p2p_core::allowlist::{AllowlistStorage, FileAllowlistStorage};
use p2p_core::identity::IdentityKey;
use p2p_core::membership::{
    ActiveMember, EvaluatedMembership, MembershipLog, Relationship, SignedMembershipEntry,
};
use tokio::sync::RwLock;

use crate::config::{MeshPaths, write_file_0600};

/// How long a pending membership grant stays valid after a successful PAKE.
pub const PENDING_GRANT_TTL: Duration = Duration::from_secs(60);

/// An in-memory grant issued after PAKE succeeds, before the signed `Add` lands.
#[derive(Debug, Clone)]
pub struct PendingGrant {
    pub device_name: String,
    pub expires_at: Instant,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn genesis_nonce() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// Owns the signed membership log and is the only writer of `allowlist.json`.
pub struct MembershipStore {
    identity: Arc<IdentityKey>,
    paths: MeshPaths,
    allowlist: Arc<FileAllowlistStorage>,
    log: RwLock<MembershipLog>,
    pending_grants: RwLock<HashMap<PeerId, PendingGrant>>,
    self_id: PeerId,
    device_name: String,
}

impl std::fmt::Debug for MembershipStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipStore")
            .field("self_id", &self.self_id)
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

impl MembershipStore {
    /// Load `membership.json`, or create a solo `Genesis` log on first boot.
    ///
    /// No Phase 3 migration: a missing `membership.json` means a fresh solo
    /// device, and the genesis entry becomes the `mesh_id`.
    pub async fn load_or_init(
        identity: Arc<IdentityKey>,
        paths: MeshPaths,
        allowlist: Arc<FileAllowlistStorage>,
        device_name: String,
    ) -> Result<Self> {
        let self_id = identity.peer_id();
        let log = match std::fs::read_to_string(&paths.membership) {
            Ok(text) => serde_json::from_str::<MembershipLog>(&text)
                .with_context(|| format!("parse {}", paths.membership.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                MembershipLog::new_genesis(&identity, &device_name, &genesis_nonce(), now_ms())
                    .map_err(|e| anyhow::anyhow!("create solo genesis: {e}"))?
            }
            Err(e) => {
                return Err(e).with_context(|| format!("read {}", paths.membership.display()));
            }
        };
        let store = Self {
            identity,
            paths,
            allowlist,
            log: RwLock::new(log),
            pending_grants: RwLock::new(HashMap::new()),
            self_id,
            device_name,
        };
        store.persist().await?;
        store.project_to_allowlist().await?;
        Ok(store)
    }

    pub fn self_id(&self) -> PeerId {
        self.self_id
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub async fn log_snapshot(&self) -> MembershipLog {
        self.log.read().await.clone()
    }

    pub async fn mesh_id(&self) -> String {
        self.log.read().await.mesh_id.clone()
    }

    pub async fn is_solo_genesis(&self) -> bool {
        self.log.read().await.entries.len() == 1
    }

    pub async fn evaluate(&self) -> EvaluatedMembership {
        self.log.read().await.evaluate()
    }

    pub async fn active_member(&self, peer: &PeerId) -> Option<ActiveMember> {
        self.evaluate().await.active.get(peer).cloned()
    }

    pub async fn is_active(&self, peer: &PeerId) -> bool {
        self.evaluate().await.active.contains_key(peer)
    }

    pub async fn active_peer_ids(&self) -> Vec<PeerId> {
        self.evaluate().await.active.keys().copied().collect()
    }

    pub async fn revoked_peers(&self) -> Vec<PeerId> {
        self.evaluate().await.revoked.keys().copied().collect()
    }

    /// Admit `peer` iff it is an active member or holds an unexpired pending
    /// grant. Expired grants are cleaned up on every check.
    pub async fn is_active_or_pending(&self, peer: &PeerId) -> bool {
        if self.is_active(peer).await {
            return true;
        }
        let mut grants = self.pending_grants.write().await;
        let now = Instant::now();
        grants.retain(|_, g| g.expires_at > now);
        grants.contains_key(peer)
    }

    /// Record an in-memory grant after PAKE succeeds (never written to disk).
    pub async fn grant_pending(&self, peer: PeerId, device_name: String) {
        self.pending_grants.write().await.insert(
            peer,
            PendingGrant {
                device_name,
                expires_at: Instant::now() + PENDING_GRANT_TTL,
            },
        );
    }

    pub async fn clear_pending(&self, peer: &PeerId) {
        self.pending_grants.write().await.remove(peer);
    }

    /// Sign an `Add` for `subject` on top of the current heads.
    pub async fn sign_add(
        &self,
        subject: PeerId,
        device_name: &str,
        relationship: Relationship,
    ) -> Result<SignedMembershipEntry> {
        let log = self.log.read().await.clone();
        log.sign_add(&self.identity, subject, device_name, relationship, now_ms())
            .map_err(|e| anyhow::anyhow!("sign membership add: {e}"))
    }

    /// Sign a `Remove` for `subject` on top of the current heads.
    pub async fn sign_remove(&self, subject: PeerId) -> Result<SignedMembershipEntry> {
        let log = self.log.read().await.clone();
        log.sign_remove(&self.identity, subject, now_ms())
            .map_err(|e| anyhow::anyhow!("sign membership remove: {e}"))
    }

    /// Sign a fresh solo `Genesis` (a new `mesh_id`).
    pub async fn new_genesis(&self) -> Result<MembershipLog> {
        MembershipLog::new_genesis(
            &self.identity,
            &self.device_name,
            &genesis_nonce(),
            now_ms(),
        )
        .map_err(|e| anyhow::anyhow!("create solo genesis: {e}"))
    }

    /// Merge one signed entry, persist, and re-project the allowlist.
    pub async fn append_entry(&self, entry: SignedMembershipEntry) -> Result<()> {
        {
            let mut log = self.log.write().await;
            log.merge_entries(std::slice::from_ref(&entry))
                .map_err(|e| anyhow::anyhow!("merge membership entry: {e}"))?;
        }
        self.persist().await?;
        self.project_to_allowlist().await?;
        Ok(())
    }

    /// Merge many entries; returns the peers that became revoked by this merge.
    pub async fn merge_entries(&self, entries: &[SignedMembershipEntry]) -> Result<Vec<PeerId>> {
        let before: Vec<PeerId> = self.evaluate().await.revoked.keys().copied().collect();
        {
            let mut log = self.log.write().await;
            log.merge_entries(entries)
                .map_err(|e| anyhow::anyhow!("merge membership entries: {e}"))?;
        }
        self.persist().await?;
        self.project_to_allowlist().await?;
        let after = self.evaluate().await;
        Ok(after
            .revoked
            .keys()
            .copied()
            .filter(|p| !before.contains(p))
            .collect())
    }

    /// Adopt a sponsor log wholesale (Case 2: the joiner is solo).
    ///
    /// Every entry is verified before the log replaces the local one, so a
    /// hostile sponsor cannot inject an unverified entry.
    pub async fn adopt_log(&self, incoming: MembershipLog) -> Result<()> {
        for entry in incoming.entries.values() {
            if !entry.verify() {
                bail!("adopted membership log has an invalid entry {}", entry.entry_id);
            }
            if entry.mesh_id() != incoming.mesh_id {
                bail!("adopted membership log entry has a mismatched mesh_id");
            }
        }
        *self.log.write().await = incoming;
        self.persist().await?;
        self.project_to_allowlist().await?;
        Ok(())
    }

    /// Replace the log with a fresh solo genesis and clear the allowlist.
    pub async fn reset_to_genesis(&self) -> Result<()> {
        let fresh = self.new_genesis().await?;
        *self.log.write().await = fresh;
        self.persist().await?;
        self.allowlist
            .save_peers(&[])
            .await
            .context("clear allowlist.json on re-genesis")?;
        Ok(())
    }

    /// Atomic `membership.json` write: temp file + rename, mode `0600`.
    async fn persist(&self) -> Result<()> {
        let log = self.log.read().await.clone();
        let bytes = serde_json::to_vec_pretty(&log).context("serialize membership.json")?;
        let tmp = self.paths.membership.with_extension("json.tmp");
        write_file_0600(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.paths.membership)
            .with_context(|| format!("rename {}", self.paths.membership.display()))?;
        Ok(())
    }

    /// The single writer of `allowlist.json`: a full overwrite from the
    /// evaluated signed log, never a merge.
    pub async fn project_to_allowlist(&self) -> Result<()> {
        let eval = self.evaluate().await;
        let existing: HashMap<PeerId, Option<u64>> = self
            .allowlist
            .list_peers()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|p| (p.node_id, p.last_seen))
            .collect();
        let projected = eval.to_allowed_peers(&self.self_id, &existing);
        self.allowlist
            .save_peers(&projected)
            .await
            .context("project membership log into allowlist.json")?;
        Ok(())
    }
}
