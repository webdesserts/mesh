//! Mesh HTTP proxy: forwards loopback HTTP requests from a remote peer to a
//! local app, with a **per-bi-stream** allowlist re-check (C1(a)).
//!
//! `p2p-core`'"'"'s `AllowlistProtocolHandler` gates once per *connection*, so a
//! bi-stream opened after revocation on an already-open connection still
//! succeeds. `MeshHttpProxyHandler` re-checks `is_allowed` for every bi-stream
//! and closes the connection with `VarInt(1)` / `"not in allowlist"` when the
//! peer is no longer paired.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use p2p_core::PeerId;
use p2p_core::allowlist::AllowlistStorage;
use p2p_core::node::P2pNode;
use p2p_core::peer_addr::PeerAddr;
use p2p_core::protocol::{AcceptError, ProtocolHandler};
use p2p_core::streams::{read_length_prefixed, write_length_prefixed};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::AppTargetConfig;

/// ALPN for the mesh HTTP proxy.
pub const HTTP_PROXY_ALPN: &[u8] = b"webdesserts/mesh/http/1";

/// Close code used when a peer is not (or no longer) in the allowlist.
pub const NOT_IN_ALLOWLIST_CODE: u32 = 1;
pub const NOT_IN_ALLOWLIST_REASON: &[u8] = b"not in allowlist";

/// Hard cap on a proxied body (request or response), in bytes.
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Upstream request timeout.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(25);

/// Headers that must never be forwarded across the mesh.
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// True when a header must be stripped before forwarding.
pub fn is_hop_by_hop(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    HOP_BY_HOP.contains(&lower.as_str())
}

/// True when the request asks for a streaming transport we do not proxy.
pub fn is_streaming_request(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        let k = k.to_ascii_lowercase();
        let v = v.to_ascii_lowercase();
        k == "upgrade" || (k == "accept" && v.contains("text/event-stream"))
    })
}

/// Convert an iroh endpoint id into a `p2p-core` `PeerId`.
pub fn peer_id_of(conn: &Connection) -> PeerId {
    PeerId::from_bytes(*conn.remote_id().as_bytes())
}

/// Request envelope (metadata frame; the body follows as its own frame).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub app_id: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body_len: u64,
}

/// Response envelope (metadata frame; the body follows as its own frame).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_len: u64,
}

/// Cached per-peer QUIC connections, so one HTTP request does not pay a fresh
/// handshake. A cached connection is reused only while it is still open.
pub type ConnPool = Arc<Mutex<HashMap<PeerId, Connection>>>;

pub fn new_pool() -> ConnPool {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Reuse a cached open connection to `peer`, or dial and cache a new one.
pub async fn dial_cached(pool: &ConnPool, node: &P2pNode, peer: PeerId) -> Result<Connection> {
    let mut guard = pool.lock().await;
    if let Some(conn) = guard.get(&peer) {
        if conn.close_reason().is_none() {
            return Ok(conn.clone());
        }
        guard.remove(&peer);
    }
    let conn = node
        .connect(&PeerAddr::new(peer), HTTP_PROXY_ALPN)
        .await
        .context("connect to peer")?;
    guard.insert(peer, conn.clone());
    Ok(conn)
}

/// Handler that serves the mesh HTTP proxy ALPN.
#[derive(Debug, Clone)]
pub struct MeshHttpProxyHandler<A: AllowlistStorage + Debug + 'static> {
    allowlist: Arc<A>,
    apps: Arc<HashMap<String, AppTargetConfig>>,
    client: reqwest::Client,
}

impl<A: AllowlistStorage + Debug + Send + Sync + 'static> MeshHttpProxyHandler<A> {
    pub fn new(allowlist: Arc<A>, apps: Arc<HashMap<String, AppTargetConfig>>) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(UPSTREAM_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            allowlist,
            apps,
            client,
        }
    }

    /// Device name recorded for `peer`, if paired.
    async fn device_name(&self, peer: &PeerId) -> Option<String> {
        let peers = self.allowlist.list_peers().await.ok()?;
        peers
            .into_iter()
            .find(|p| &p.node_id == peer && !p.removed)
            .map(|p| p.device_name)
    }

    /// Write a bare status response (no body) and finish the stream.
    async fn write_status(&self, send: &mut SendStream, status: u16) -> Result<()> {
        let out = ProxyResponse {
            status,
            headers: Vec::new(),
            body_len: 0,
        };
        write_length_prefixed(send, &serde_json::to_vec(&out)?)
            .await
            .context("write status frame")?;
        let _ = send.finish();
        Ok(())
    }

    /// Forward one bi-stream to the local app and write the response back.
    async fn serve(&self, mut send: SendStream, mut recv: RecvStream, peer: PeerId) -> Result<()> {
        let meta = read_length_prefixed(&mut recv)
            .await
            .context("read request frame")?;
        let req: ProxyRequest = serde_json::from_slice(&meta).context("parse request frame")?;

        // Cap the declared body length before allocating anything.
        if req.body_len > MAX_BODY_BYTES as u64 {
            self.write_status(&mut send, 413).await?;
            return Ok(());
        }

        let body = if req.body_len > 0 {
            read_length_prefixed(&mut recv)
                .await
                .context("read request body")?
        } else {
            Vec::new()
        };
        if body.len() > MAX_BODY_BYTES {
            self.write_status(&mut send, 413).await?;
            return Ok(());
        }

        // Streaming transports (SSE / WebSocket upgrade) are not proxied.
        if is_streaming_request(&req.headers) {
            self.write_status(&mut send, 400).await?;
            return Ok(());
        }

        let target = match self.apps.get(&req.app_id) {
            Some(t) => t.clone(),
            None => {
                self.write_status(&mut send, 404).await?;
                return Ok(());
            }
        };
        let port = match target.resolved_port() {
            Ok(p) => p,
            Err(_) => {
                self.write_status(&mut send, 502).await?;
                return Ok(());
            }
        };

        // Read-only apps (e.g. `notes`) accept only safe methods.
        let method_upper = req.method.to_ascii_uppercase();
        if target.read_only && method_upper != "GET" && method_upper != "HEAD" {
            self.write_status(&mut send, 403).await?;
            return Ok(());
        }

        let url = format!("http://127.0.0.1:{port}{}", req.path);
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .with_context(|| format!("bad method {:?}", req.method))?;

        let mut builder = self.client.request(method, url);
        for (k, v) in &req.headers {
            let lower = k.to_ascii_lowercase();
            // Strip hop-by-hop, identity, and Host: the upstream Host must name
            // the local app, never the mesh peer.
            if is_hop_by_hop(&lower) || lower.starts_with("x-mesh-") || lower == "host" {
                continue;
            }
            builder = builder.header(k.as_str(), v.as_str());
        }
        builder = builder.header("host", format!("127.0.0.1:{port}"));

        // Identity headers are authoritative: always overwrite, never trust
        // an inbound copy (spoof protection).
        // v0: all paired peers are self (every allowlisted peer is one of
        // Michael'"'"'s own devices). Revisit when sharing arrives.
        let relationship = "self";
        builder = builder.header("x-mesh-peer-id", peer.to_string());
        builder = builder.header("x-mesh-relationship", relationship);
        if let Some(name) = self.device_name(&peer).await {
            builder = builder.header("x-mesh-device-name", name);
        }

        if !body.is_empty() {
            builder = builder.body(body);
        }

        let resp = match builder.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "local app unreachable");
                self.write_status(&mut send, 502).await?;
                return Ok(());
            }
        };
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter(|(k, _)| !is_hop_by_hop(k.as_str()))
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        let bytes = resp.bytes().await.context("read local app body")?;
        if bytes.len() > MAX_BODY_BYTES {
            self.write_status(&mut send, 502).await?;
            return Ok(());
        }

        let out = ProxyResponse {
            status,
            headers,
            body_len: bytes.len() as u64,
        };
        write_length_prefixed(&mut send, &serde_json::to_vec(&out)?)
            .await
            .context("write response frame")?;
        if !bytes.is_empty() {
            write_length_prefixed(&mut send, &bytes)
                .await
                .context("write response body")?;
        }
        let _ = send.finish();
        Ok(())
    }
}

impl<A: AllowlistStorage + Debug + Send + Sync + 'static> ProtocolHandler
    for MeshHttpProxyHandler<A>
{
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer = peer_id_of(&connection);

        // Close an unpaired peer immediately, before it can hold an idle
        // connection open for free (one extra lookup, strictly stronger).
        if !self.allowlist.is_allowed(&peer).await.unwrap_or(false) {
            connection.close(
                VarInt::from_u32(NOT_IN_ALLOWLIST_CODE),
                NOT_IN_ALLOWLIST_REASON,
            );
            return Ok(());
        }

        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(bi) => bi,
                // Peer closed the connection (or it was closed by us).
                Err(_) => return Ok(()),
            };

            // C1(a): re-check the allowlist for EVERY bi-stream, not once per
            // connection. A revoked peer must not ride an already-open conn.
            let allowed = self.allowlist.is_allowed(&peer).await.unwrap_or(false);
            if !allowed {
                connection.close(
                    VarInt::from_u32(NOT_IN_ALLOWLIST_CODE),
                    NOT_IN_ALLOWLIST_REASON,
                );
                return Ok(());
            }

            if let Err(e) = self.serve(send, recv, peer).await {
                tracing::warn!(error = %e, "mesh proxy bi-stream failed");
            }
        }
    }
}

/// Client side: forward `req` (and `body`) to `peer` over a pooled connection.
pub async fn forward_with_body(
    pool: &ConnPool,
    node: &P2pNode,
    peer: PeerId,
    mut req: ProxyRequest,
    body: Vec<u8>,
) -> Result<(ProxyResponse, Vec<u8>)> {
    if body.len() > MAX_BODY_BYTES {
        bail!("request body exceeds {MAX_BODY_BYTES} bytes");
    }
    req.body_len = body.len() as u64;

    let conn = dial_cached(pool, node, peer).await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open bi-stream")?;

    write_length_prefixed(&mut send, &serde_json::to_vec(&req)?)
        .await
        .context("write request frame")?;
    if !body.is_empty() {
        write_length_prefixed(&mut send, &body)
            .await
            .context("write request body")?;
    }
    let _ = send.finish();

    let meta = read_length_prefixed(&mut recv)
        .await
        .context("read response frame")?;
    let resp: ProxyResponse = serde_json::from_slice(&meta).context("parse response frame")?;
    if resp.body_len > MAX_BODY_BYTES as u64 {
        return Err(anyhow!("response body exceeds {MAX_BODY_BYTES} bytes"));
    }
    let resp_body = if resp.body_len > 0 {
        read_length_prefixed(&mut recv)
            .await
            .context("read response body")?
    } else {
        Vec::new()
    };
    Ok((resp, resp_body))
}
