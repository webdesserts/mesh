//! Loopback HTTP API for the mesh daemon (`127.0.0.1:4620`).
//!
//! Every route is guarded by [`csrf_guard`]: a request carrying an `Origin`
//! header (a browser cross-origin call) or a non-loopback `Host` is refused
//! with `403`. The API is loopback-only by construction.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use p2p_core::PeerId;
use p2p_core::allowlist::{AllowlistStorage, FileAllowlistStorage};
use p2p_core::gossip::GossipHandle;
use p2p_core::node::P2pNode;
use p2p_core::pairing::PairingHello;
use p2p_core::pairing_handler::pair_with_mesh;
use p2p_core::peer_addr::PeerAddr;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::AppTargetConfig;
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
        .layer(axum::middleware::from_fn(csrf_guard))
        .with_state(state)
}

/// Bind and serve until cancelled.
pub async fn serve(state: Arc<ApiState>, addr: &str) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[derive(Serialize)]
struct StatusResp {
    device_name: String,
    peer_id: String,
    listen_addr: String,
    apps: Vec<String>,
    peers: usize,
}

async fn status(State(st): State<Arc<ApiState>>) -> Response {
    let peers = st.allowlist.list_peers().await.map(|p| p.len()).unwrap_or(0);
    Json(StatusResp {
        device_name: st.device_name.clone(),
        peer_id: st.self_id.to_string(),
        listen_addr: crate::config::DEFAULT_LISTEN_ADDR.to_string(),
        apps: st.apps.keys().cloned().collect(),
        peers,
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
async fn poke(State(st): State<Arc<ApiState>>, Json(req): Json<PokeReq>) -> Response {
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
            let _ = h.broadcast(Bytes::from(bytes));
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
    #[serde(default)]
    timeout_ms: u64,
}

/// Long-poll: return pokes with `seq > since`, or an empty list on timeout.
///
/// Uses `watch` (not `Notify`): every concurrent poller sees every bump, so a
/// second `GET /pokes` is not left waiting until `timeout_ms`.
async fn pokes(State(st): State<Arc<ApiState>>, Query(q): Query<PokesQuery>) -> Response {
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(q.timeout_ms.min(30_000));
    let mut rx = st.inbox.subscribe();
    loop {
        let got = st.inbox.since(q.since, q.app_id.as_deref());
        if !got.is_empty() {
            return Json(got).into_response();
        }
        if tokio::time::Instant::now() >= deadline {
            return Json(Vec::<StoredPoke>::new()).into_response();
        }
        tokio::select! {
            _ = rx.changed() => {}
            _ = tokio::time::sleep_until(deadline) => {
                return Json(Vec::<StoredPoke>::new()).into_response();
            }
        }
    }
}

#[derive(Deserialize)]
struct PairReq {
    peer: String,
    code: String,
    #[serde(default)]
    device_name: Option<String>,
}

/// Pair with a peer, then persist it in the allowlist and join it to gossip.
async fn pair(State(st): State<Arc<ApiState>>, Json(req): Json<PairReq>) -> Response {
    let peer: PeerId = match req.peer.parse() {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let name = req
        .device_name
        .clone()
        .unwrap_or_else(|| st.device_name.clone());
    let hello = PairingHello {
        node_id: st.self_id,
        device_name: name.clone(),
    };
    let dial = st.node.dial_handle();
    match pair_with_mesh(&dial, PeerAddr::new(peer), &hello, &req.code).await {
        Ok(res) => {
            if res.success {
                if let Err(e) = st.allowlist.add_peer(peer, &name).await {
                    tracing::warn!(error = %e, "persist paired peer failed");
                }
                let guard = st.gossip.lock().await;
                if let Some(h) = guard.as_ref() {
                    let _ = h.rejoin_peers(vec![peer]);
                }
            }
            Json(res).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}
