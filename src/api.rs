//! Loopback HTTP API for the mesh daemon (`127.0.0.1:4620`).
//!
//! Every route is guarded by [`csrf_guard`]: a request carrying an `Origin`
//! header (a browser cross-origin call) or a non-loopback `Host` is refused
//! with `403`. The API is loopback-only by construction.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use p2p_core::PeerId;
use p2p_core::allowlist::{AllowlistStorage, FileAllowlistStorage};
use p2p_core::gossip::GossipHandle;
use p2p_core::node::P2pNode;
use p2p_core::pairing::{PairingHello, generate_pairing_code};
use p2p_core::pairing_handler::pair_with_mesh_interactive;
use p2p_core::peer_addr::PeerAddr;
use p2p_core::relay_addr::RelayAddr;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use std::collections::BTreeMap;

use crate::config::AppTargetConfig;
use crate::membership_store::MembershipStore;
use crate::membership_sync::MeshWireMessage;
use crate::register::RegistrationStore;
use p2p_core::membership::{Relationship, SignedMembershipEntry};
use crate::poke::{MeshPokeWire, SharedPokeInbox, StoredPoke};
use crate::proxy::{ConnPool, MAX_BODY_BYTES, ProxyRequest, forward_with_body};

/// Shared state for every route.
pub struct ApiState {
    pub node: Arc<P2pNode>,
    pub allowlist: Arc<FileAllowlistStorage>,
    pub apps: Arc<HashMap<String, AppTargetConfig>>,
    pub inbox: SharedPokeInbox,
    /// Shared with the daemon so `/poke` broadcasts on the live subscription.
    pub gossip: Arc<Mutex<Option<GossipHandle>>>,
    /// Cached per-peer QUIC connections (one handshake, not one per request).
    pub pool: ConnPool,
    pub device_name: String,
    pub self_id: PeerId,
    /// Public relays this node knows; attached to `PeerAddr` when dialing.
    pub relays: Vec<RelayAddr>,
    /// Single-use pairing code armed by `POST /pair/code`.
    pub pending_pairing: Arc<Mutex<Option<crate::PendingPairing>>>,
    /// Loopback health URL of `NotesSync.app`, probed by `GET /status`.
    pub notes_health_url: String,
    /// Whether the daemon started an embedded relay.
    pub relay_listen: bool,
    /// Signed membership log: the source of truth for the allowlist projection.
    pub membership: Arc<MembershipStore>,
    /// Dynamically registered apps + admin token.
    pub registrations: Arc<RegistrationStore>,
    /// Single shared health-probe client (500ms timeout).
    pub health_client: reqwest::Client,
    /// Loopback API port (reserved from dynamic app registration).
    pub listen_port: u16,
    /// Embedded relay port (reserved from dynamic app registration).
    pub relay_port: u16,
}

/// CSRF guard: refuse any request with an `Origin` header or a non-loopback
/// `Host`. Fails closed when `Host` is absent.
pub async fn csrf_guard(req: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = req.headers();
    if headers.contains_key("origin") {
        return Err(StatusCode::FORBIDDEN);
    }
    let host_ok = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            let name = h.rsplit_once(":").map(|(n, _)| n).unwrap_or(h);
            let name = name.trim_start_matches("[").trim_end_matches("]");
            name == "127.0.0.1" || name == "localhost" || name == "::1"
        })
        .unwrap_or(false);
    if !host_ok {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(req).await)
}

/// Build the router.
pub fn router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/peer/{target}/app/{app_id}", any(proxy_root))
        .route("/peer/{target}/app/{app_id}/{*path}", any(proxy))
        .route("/poke", post(poke))
        .route("/pokes", get(pokes))
        .route("/pair", post(pair))
        .route("/pair/code", post(pair_code))
        .route("/membership", get(membership_get))
        .route("/membership/remove", post(membership_remove))
        .route("/membership/genesis", post(membership_genesis))
        .route("/revoke", post(revoke))
        .route("/apps/register", post(apps_register))
        .route("/apps/unregister", post(apps_unregister))
        .route("/register", post(apps_register))
        .layer(axum::middleware::from_fn(csrf_guard))
        .with_state(state)
}

/// TCP router: mutating management routes additionally require the admin token
/// (Colima containers can reach host `127.0.0.1:4620` via `host.docker.internal`).
pub fn tcp_router(state: Arc<ApiState>) -> Router {
    let guard_state = state.clone();
    router(state).layer(axum::middleware::from_fn_with_state(
        guard_state,
        admin_guard,
    ))
}

/// Mutating management routes that require `Authorization: Bearer <admin.token>`
/// when reached over loopback TCP.
fn is_mutating_management(method: &axum::http::Method, path: &str) -> bool {
    if method != axum::http::Method::POST {
        return false;
    }
    matches!(
        path,
        "/pair"
            | "/pair/code"
            | "/membership/remove"
            | "/membership/genesis"
            | "/revoke"
            | "/apps/register"
            | "/apps/unregister"
            | "/register"
    )
}

/// Admin-token guard for mutating management routes over TCP.
pub async fn admin_guard(
    State(st): State<Arc<ApiState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if is_mutating_management(req.method(), req.uri().path()) {
        let presented = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !st.registrations.admin_token_matches(presented) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(next.run(req).await)
}

/// Bind and serve until cancelled.
pub async fn serve(state: Arc<ApiState>, addr: &str) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, tcp_router(state)).await?;
    Ok(())
}

#[derive(Serialize)]
struct StatusResp {
    device_name: String,
    peer_id: String,
    listen_addr: String,
    apps: Vec<String>,
    peers: usize,
    relay_listen: bool,
    poke_epoch: u64,
    latest_poke_seq: u64,
    notes_sync_healthy: bool,
    mesh_id: String,
}

/// Probe `NotesSync.app`'"'"'s loopback health endpoint with a 500ms timeout.
async fn notes_sync_healthy(client: &reqwest::Client, url: &str) -> bool {
    match client.get(url).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

async fn status(State(st): State<Arc<ApiState>>) -> Response {
    let peers = st.allowlist.list_peers().await.map(|p| p.len()).unwrap_or(0);
    let healthy = notes_sync_healthy(&st.health_client, &st.notes_health_url).await;
    let mut apps: Vec<String> = st.apps.keys().cloned().collect();
    for name in st.registrations.snapshot().await.apps.keys() {
        if !apps.contains(name) {
            apps.push(name.clone());
        }
    }
    Json(StatusResp {
        device_name: st.device_name.clone(),
        peer_id: st.self_id.to_string(),
        listen_addr: crate::config::DEFAULT_LISTEN_ADDR.to_string(),
        apps,
        mesh_id: st.membership.mesh_id().await,
        peers,
        relay_listen: st.relay_listen,
        poke_epoch: st.inbox.epoch(),
        latest_poke_seq: st.inbox.latest_seq(),
        notes_sync_healthy: healthy,
    })
    .into_response()
}

/// Resolve `:target` as a 64-char hex `PeerId` or a case-insensitive
/// `device_name` from the allowlist. `404` when neither matches.
async fn resolve_target(st: &ApiState, target: &str) -> Result<PeerId, StatusCode> {
    if let Ok(p) = target.parse::<PeerId>() {
        return Ok(p);
    }
    let peers = st
        .allowlist
        .list_peers()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    peers
        .into_iter()
        .find(|p| !p.removed && p.device_name.eq_ignore_ascii_case(target))
        .map(|p| p.node_id)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Forward one request to the target peer app over the mesh proxy ALPN.
/// App-scoped bearer token (S4): a dynamically registered app must present
/// `Authorization: Bearer <token>` (or the admin token) on `/poke`, `/pokes`,
/// and `/peer/.../app/...`. Static `config.toml` apps stay loopback-trusted so
/// existing Phase 2/3 callers are unchanged.
async fn dynamic_app_token_ok(st: &ApiState, app_id: &str, headers: &HeaderMap) -> bool {
    if st.apps.contains_key(app_id) {
        return true;
    }
    if st.registrations.get(app_id).await.is_none() {
        // Unknown app: let the handler produce its own 404.
        return true;
    }
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    st.registrations.verify_token(app_id, presented).await
        || st.registrations.admin_token_matches(presented)
}

async fn proxy_inner(
    st: Arc<ApiState>,
    target: String,
    app_id: String,
    rest: String,
    req: Request,
) -> Response {
    let peer = match resolve_target(&st, &target).await {
        Ok(p) => p,
        Err(code) => return code.into_response(),
    };

    let (parts, body) = req.into_parts();
    if !dynamic_app_token_ok(&st, &app_id, &parts.headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let body_bytes = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();

    // Preserve the query string: `Path` extraction strips it.
    let base_path = format!("/{}", rest.trim_start_matches("/"));
    let path = match parts.uri.query() {
        Some(q) if !q.is_empty() => format!("{base_path}?{q}"),
        _ => base_path,
    };

    let preq = ProxyRequest {
        app_id,
        method: parts.method.to_string(),
        path,
        headers,
        body_len: body_bytes.len() as u64,
    };

    match forward_with_body(&st.pool, &st.node, peer, preq, body_bytes.to_vec()).await {
        Ok((resp, body)) => {
            let mut builder = Response::builder()
                .status(StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY));
            for (k, v) in resp.headers {
                builder = builder.header(k, v);
            }
            builder
                .body(Body::from(body))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(e) => {
            tracing::warn!(error = %e, "mesh proxy forward failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn proxy(
    State(st): State<Arc<ApiState>>,
    Path((target, app_id, rest)): Path<(String, String, String)>,
    req: Request,
) -> Response {
    proxy_inner(st, target, app_id, rest, req).await
}

/// Root app path (`/peer/{target}/app/{app_id}`) forwards to `/`.
async fn proxy_root(
    State(st): State<Arc<ApiState>>,
    Path((target, app_id)): Path<(String, String)>,
    req: Request,
) -> Response {
    proxy_inner(st, target, app_id, String::new(), req).await
}

#[derive(Deserialize)]
struct PokeReq {
    #[serde(alias = "appId")]
    app_id: String,
    #[serde(default)]
    topic: String,
    cursor: String,
}

/// Broadcast a poke. `seq` is receiver-local, so the sender returns no seq.
async fn poke(
    State(st): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(req): Json<PokeReq>,
) -> Response {
    if !dynamic_app_token_ok(&st, &req.app_id, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let wire = MeshPokeWire {
        app_id: req.app_id,
        topic: req.topic,
        cursor: req.cursor,
        sender_peer_id: st.self_id.to_string(),
        timestamp_ms: now_ms(),
        // iroh-gossip dedups by content; a random nonce keeps repeated
        // cursors from being dropped as duplicates.
        nonce: rand::random::<u64>(),
    };
    let bytes = match serde_json::to_vec(&wire) {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let guard = st.gossip.lock().await;
    match guard.as_ref() {
        Some(h) => {
            if let Err(e) = h.broadcast(Bytes::from(bytes)).await {
                tracing::warn!(error = %e, "gossip broadcast failed");
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct PokesQuery {
    #[serde(rename = "appId")]
    app_id: Option<String>,
    #[serde(default)]
    since: u64,
    /// Per-boot epoch from a previous response; a mismatch means the daemon
    /// restarted and the caller'"'"'s cursor is stale.
    #[serde(default)]
    epoch: Option<u64>,
    #[serde(default)]
    timeout_ms: u64,
}

/// Response envelope for `GET /pokes`.
///
/// `truncated` is `true` when the caller'"'"'s cursor is unusable (epoch mismatch,
/// `since` ahead of the latest seq, or ring-buffer eviction); in that case the
/// server resets to `since = 0` and returns every buffered poke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PokesResp {
    pub epoch: u64,
    pub latest_seq: u64,
    pub truncated: bool,
    pub pokes: Vec<StoredPoke>,
}

fn pokes_resp(st: &ApiState, truncated: bool, pokes: Vec<StoredPoke>) -> Response {
    Json(PokesResp {
        epoch: st.inbox.epoch(),
        latest_seq: st.inbox.latest_seq(),
        truncated,
        pokes,
    })
    .into_response()
}

/// Long-poll: return pokes with `seq > since`, or an empty list on timeout.
///
/// Uses `watch` (not `Notify`): every concurrent poller sees every bump, so a
/// second `GET /pokes` is not left waiting until `timeout_ms`. The effective
/// `since` (0 after a restart/eviction) drives both the first read and the
/// long-poll wake check.
async fn pokes(
    State(st): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(q): Query<PokesQuery>,
) -> Response {
    if let Some(app_id) = q.app_id.as_deref() {
        if !dynamic_app_token_ok(&st, app_id, &headers).await {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(q.timeout_ms.min(30_000));
    let mut rx = st.inbox.subscribe();
    let (immediate, truncated, effective_since) =
        st.inbox.read_since(q.since, q.epoch, q.app_id.as_deref());
    if !immediate.is_empty() || truncated || q.timeout_ms == 0 {
        return pokes_resp(&st, truncated, immediate);
    }
    loop {
        let (got, trunc, _) =
            st.inbox
                .read_since(effective_since, Some(st.inbox.epoch()), q.app_id.as_deref());
        if !got.is_empty() || trunc {
            return pokes_resp(&st, trunc, got);
        }
        if tokio::time::Instant::now() >= deadline {
            return pokes_resp(&st, false, Vec::new());
        }
        tokio::select! {
            _ = rx.changed() => {}
            _ = tokio::time::sleep_until(deadline) => {
                return pokes_resp(&st, false, Vec::new());
            }
        }
    }
}

#[derive(Deserialize)]
struct PairReq {
    peer: String,
    code: String,
    /// Optional friendly name override for the remote peer in our local
    /// allowlist. When omitted, the acceptor'"'"'s `challenge.device_name` from the
    /// handshake is used.
    #[serde(default)]
    peer_device_name: Option<String>,
    /// Optional relay URL override; when omitted, all `st.relays` are attached.
    #[serde(default)]
    relay_url: Option<String>,
}

/// Arm a single-use 6-digit pairing code on this (acceptor) node.
///
/// The first non-revoked inbound pairing request consumes it, so an attacker
/// minting fresh `PeerId`s over the public relay cannot brute-force it.
async fn pair_code(State(st): State<Arc<ApiState>>) -> Response {
    let code = generate_pairing_code();
    let pending = crate::PendingPairing {
        code: code.clone(),
        expires_at: std::time::Instant::now() + crate::PAIRING_CODE_TTL,
    };
    *st.pending_pairing.lock().await = Some(pending);
    tracing::info!("armed single-use mesh pairing code (valid 300s)");
    Json(serde_json::json!({
        "code": code,
        "expires_in_secs": crate::PAIRING_CODE_TTL.as_secs(),
    }))
    .into_response()
}

/// Pair with a peer, then persist it in the allowlist and join it to gossip.
async fn pair(State(st): State<Arc<ApiState>>, Json(req): Json<PairReq>) -> Response {
    let peer: PeerId = match req.peer.parse() {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    // S2: refuse a tombstoned peer before dialing.
    match st.allowlist.list_peers().await {
        Ok(peers) => {
            if peers.iter().any(|p| p.node_id == peer && p.removed) {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({ "error": "peer is revoked" })),
                )
                    .into_response();
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "read allowlist before pairing failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    // S1c: a peer revoked in the signed log must fail closed before dialing,
    // otherwise the membership gate refuses the PAKE dial and we report 502.
    if st.membership.evaluate().await.revoked.contains_key(&peer) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "peer key is revoked in membership log; rotate key first"
            })),
        )
            .into_response();
    }
    // Our own configured device name is authoritative on the wire.
    let hello = PairingHello {
        node_id: st.self_id,
        device_name: st.device_name.clone(),
    };
    let mut peer_addr = PeerAddr::new(peer);
    if let Some(ref url_str) = req.relay_url {
        match RelayAddr::parse(url_str) {
            Ok(r) => peer_addr = peer_addr.with_relay(r),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        }
    } else {
        for r in &st.relays {
            peer_addr = peer_addr.with_relay(r.clone());
        }
    }
    let dial = st.node.dial_handle();
    let captured: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let captured_clone = captured.clone();
    let code = req.code.clone();
    let res = pair_with_mesh_interactive(&dial, peer_addr, &hello, move |challenge| {
        *captured_clone.lock().unwrap() = Some(challenge.device_name);
        async move { Ok(code) }
    })
    .await;
    match res {
        Ok(res) => {
            if res.success {
                // S1: prefer the acceptor'"'"'s real device name from the handshake.
                let desired = req
                    .peer_device_name
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| captured.lock().unwrap().clone())
                    .unwrap_or_else(|| {
                        let hex = peer.to_string();
                        format!("peer-{}", &hex[..8.min(hex.len())])
                    });
                for r in &st.relays {
                    st.node.add_peer_relay(peer, r);
                }
                for url in &res.relay_urls {
                    if let Ok(r) = RelayAddr::parse(url) {
                        st.node.add_peer_relay(peer, &r);
                    }
                }
                // S1a: record an in-memory pending grant, then run the signed
                // membership handshake. `allowlist.json` is never written here.
                st.membership.grant_pending(peer, desired.clone()).await;
                match crate::membership_sync::pair_sync_initiator(
                    &st.node,
                    peer,
                    &st.membership,
                    &desired,
                )
                .await
                {
                    Ok(log) => tracing::info!(
                        peer = %peer,
                        entries = log.entries.len(),
                        "mesh pairing completed (signed membership)"
                    ),
                    Err(e) => {
                        st.membership.clear_pending(&peer).await;
                        tracing::warn!(peer = %peer, error = %e, "membership pair sync failed");
                        return (
                            StatusCode::CONFLICT,
                            Json(serde_json::json!({ "error": e.to_string() })),
                        )
                            .into_response();
                    }
                }
                let guard = st.gossip.lock().await;
                if let Some(h) = guard.as_ref() {
                    if let Err(e) = h.rejoin_peers(vec![peer]).await {
                        tracing::warn!(peer = %peer, error = %e, "rejoin_peers after outbound pair failed");
                    }
                    // Announce our heads so already-connected neighbors pull the
                    // entries this pairing just added (NeighborUp fired earlier).
                    let log = st.membership.log_snapshot().await;
                    let wire = MeshWireMessage::AntiEntropy {
                        mesh_id: log.mesh_id.clone(),
                        heads: log.evaluate().heads,
                    };
                    if let Ok(bytes) = serde_json::to_vec(&wire) {
                        if let Err(e) = h.broadcast(Bytes::from(bytes)).await {
                            tracing::warn!(error = %e, "pair anti-entropy broadcast failed");
                        }
                    }
                }
            }
            Json(res).into_response()
        }
        Err(e) => {
            // S1c: any failure of the signed membership handshake is a
            // membership refusal (revoked / not allowlisted / mesh mismatch),
            // so report 409 Conflict rather than a transport-level 502.
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Membership management (signed log is the source of truth)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MembershipRemoveReq {
    peer: String,
}

#[derive(Deserialize)]
struct MembershipGenesisReq {
    #[serde(default)]
    force: bool,
}

/// Resolve a `PeerId` (64-char hex) or a case-insensitive `device_name`.
async fn resolve_peer(st: &ApiState, target: &str) -> Option<PeerId> {
    if let Ok(id) = target.parse::<PeerId>() {
        return Some(id);
    }
    let eval = st.membership.evaluate().await;
    eval.active
        .values()
        .find(|m| m.device_name.eq_ignore_ascii_case(target))
        .map(|m| m.peer_id)
}

/// Full revocation teardown (S3): allowlist projection is already rewritten by
/// the store; here we drop pooled connections, relay hints, and gossip peers.
async fn teardown_revoked(st: &ApiState, revoked: &[PeerId]) {
    if revoked.is_empty() {
        return;
    }
    {
        let mut pool = st.pool.lock().await;
        for peer in revoked {
            pool.remove(peer);
        }
    }
    for peer in revoked {
        st.node.remove_peer_relay(*peer);
    }
    let active = st.membership.active_peer_ids().await;
    let guard = st.gossip.lock().await;
    if let Some(h) = guard.as_ref() {
        if let Err(e) = h.rejoin_peers(active).await {
            tracing::warn!(error = %e, "gossip rejoin after revocation failed");
        }
    }
}

/// Broadcast a signed membership entry on gossip.
async fn broadcast_entry(st: &ApiState, entry: &SignedMembershipEntry) {
    let wire = MeshWireMessage::Membership(entry.clone());
    let bytes = match serde_json::to_vec(&wire) {
        Ok(b) => b,
        Err(_) => return,
    };
    let guard = st.gossip.lock().await;
    if let Some(h) = guard.as_ref() {
        if let Err(e) = h.broadcast(Bytes::from(bytes)).await {
            tracing::warn!(error = %e, "membership gossip broadcast failed");
        }
    }
}

async fn membership_get(State(st): State<Arc<ApiState>>) -> Response {
    let eval = st.membership.evaluate().await;
    let log = st.membership.log_snapshot().await;
    let active_peers: Vec<serde_json::Value> = eval
        .active
        .values()
        .map(|m| {
            serde_json::json!({
                "peer_id": m.peer_id.to_string(),
                "device_name": m.device_name,
                "relationship": match m.relationship {
                    Relationship::SelfDevice => "self",
                    Relationship::Friend => "friend",
                },
                "paired_at": m.paired_at,
            })
        })
        .collect();
    let revoked_peers: Vec<serde_json::Value> = eval
        .revoked
        .iter()
        .map(|(id, at)| serde_json::json!({ "peer_id": id.to_string(), "removed_at": at }))
        .collect();
    Json(serde_json::json!({
        "mesh_id": eval.mesh_id,
        "heads": eval.heads,
        "active_peers": active_peers,
        "revoked_peers": revoked_peers,
        "entries_count": log.entries.len(),
    }))
    .into_response()
}

async fn membership_remove(
    State(st): State<Arc<ApiState>>,
    Json(req): Json<MembershipRemoveReq>,
) -> Response {
    let target = match resolve_peer(&st, &req.peer).await {
        Some(id) => id,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "unknown peer" })),
            )
                .into_response();
        }
    };
    let entry = match st.membership.sign_remove(target).await {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
            )
                .into_response();
        }
    };
    if let Err(e) = st.membership.append_entry(entry.clone()).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response();
    }
    teardown_revoked(&st, &[target]).await;
    broadcast_entry(&st, &entry).await;
    Json(serde_json::json!({ "ok": true, "revoked": target.to_string() })).into_response()
}

async fn revoke(
    State(st): State<Arc<ApiState>>,
    Json(req): Json<MembershipRemoveReq>,
) -> Response {
    membership_remove(State(st), Json(req)).await
}

async fn membership_genesis(
    State(st): State<Arc<ApiState>>,
    Json(req): Json<MembershipGenesisReq>,
) -> Response {
    let eval = st.membership.evaluate().await;
    let self_active = eval.active.contains_key(&st.self_id);
    if self_active && !req.force {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "this device is still active; pass force=true to re-genesis"
            })),
        )
            .into_response();
    }
    if req.force && self_active {
        // Announce the self-removal into the old mesh before abandoning it.
        if let Ok(entry) = st.membership.sign_remove(st.self_id).await {
            let _ = st.membership.append_entry(entry.clone()).await;
            broadcast_entry(&st, &entry).await;
        }
    }
    if let Err(e) = st.membership.reset_to_genesis().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response();
    }
    let mesh_id = st.membership.mesh_id().await;
    Json(serde_json::json!({ "ok": true, "mesh_id": mesh_id })).into_response()
}

// ---------------------------------------------------------------------------
// Dynamic app registration (register.sock / admin-token TCP)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AppRegisterReq {
    app_id: String,
    port: u16,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    allow_friends: bool,
}

#[derive(Deserialize)]
struct AppUnregisterReq {
    app_id: String,
}

fn bearer_of(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

async fn apps_register(
    State(st): State<Arc<ApiState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AppRegisterReq>,
) -> Response {
    let static_apps: BTreeMap<String, AppTargetConfig> =
        st.apps.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let reserved = vec![st.listen_port, st.relay_port];
    let token = bearer_of(&headers);
    match st
        .registrations
        .register(
            &req.app_id,
            req.port,
            req.read_only,
            req.allow_friends,
            &static_apps,
            &reserved,
            token.as_deref(),
        )
        .await
    {
        Ok(token) => Json(serde_json::json!({
            "status": "approved",
            "app_id": req.app_id,
            "token": token,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn apps_unregister(
    State(st): State<Arc<ApiState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AppUnregisterReq>,
) -> Response {
    let token = bearer_of(&headers);
    match st
        .registrations
        .unregister(&req.app_id, token.as_deref())
        .await
    {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Serve the management + registration API over the `0600` Unix domain socket.
///
/// Callers here are pre-authenticated by OS filesystem permissions, so mutating
/// routes do not need the admin bearer token.
pub async fn serve_uds(state: Arc<ApiState>, path: std::path::PathBuf) -> anyhow::Result<()> {
    let listener = crate::register::bind_register_sock(&path)?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}
