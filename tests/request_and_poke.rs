//! Phase 2B acceptance tests (spec §6).
//!
//! 1. config: 0700 dir / 0600 file perms, daemon lock, config.toml parse.
//! 2. CSRF guard: Origin header or non-loopback Host -> 403.
//! 3. E2E request through the Axum API: `:target` device-name resolution,
//!    query-string preservation, Host rewrite, authoritative identity headers,
//!    SSE/Upgrade -> 400, read-only app POST -> 403.
//! 4. C1(a) per-bi-stream revoke: one request 200, remove_peer, second
//!    bi-stream on the SAME connection -> ApplicationClosed(VarInt(1)).
//! 5. E2E poke + long-poll over gossip, receiver-local seq.
//! 6. Two concurrent `/pokes` pollers both wake on one poke (P1).

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{OriginalUri, State as AxState};
use axum::http::HeaderMap;
use axum::routing::any;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{ConnectionError, VarInt};
use p2p_core::allowlist::{AllowlistStorage, FileAllowlistStorage};
use p2p_core::node::P2pNode;
use p2p_core::peer_addr::PeerAddr;
use p2p_core::streams::{read_length_prefixed, write_length_prefixed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use webdesserts_mesh::MeshDaemon;
use webdesserts_mesh::config::{AppTargetConfig, MeshConfig, MeshPaths};
use webdesserts_mesh::poke::{MeshPokeWire, PokeInbox, poke_topic};
use webdesserts_mesh::proxy::{HTTP_PROXY_ALPN, ProxyRequest, forward_with_body, new_pool, should_strip_header};

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

/// A fresh on-disk allowlist at a unique temp path.
fn file_allowlist(tag: &str) -> Arc<FileAllowlistStorage> {
    let path = std::env::temp_dir().join(format!("wd-mesh-allowlist-{tag}.json"));
    let _ = std::fs::remove_file(&path);
    Arc::new(FileAllowlistStorage::at_path(path))
}

/// Seed `node`'"'"'s address lookup with `peer`'"'"'s endpoint info so in-process
/// dialing works without a relay.
fn seed_lookup(node: &P2pNode, peer: &P2pNode) -> anyhow::Result<()> {
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(peer.endpoint_for_test().addr());
    node.endpoint_for_test().address_lookup()?.add(lookup);
    Ok(())
}

/// Mock app: echoes the mesh identity headers, Host, and full URI it received.
async fn mock_app(
    AxState(_): AxState<()>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> String {
    let get = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    format!(
        "peer={} device={} rel={} host={} uri={}",
        get("x-mesh-peer-id"),
        get("x-mesh-device-name"),
        get("x-mesh-relationship"),
        get("host"),
        uri
    )
}

/// Spawn the mock app on an ephemeral port; returns its port.
async fn spawn_mock_app() -> anyhow::Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route("/{*path}", any(mock_app)).with_state(());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

/// Spawn the mesh API on an ephemeral port; returns its port.
async fn spawn_api(state: Arc<webdesserts_mesh::api::ApiState>) -> anyhow::Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let router = webdesserts_mesh::api::router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(port)
}

fn api_state(
    node: Arc<P2pNode>,
    allowlist: Arc<FileAllowlistStorage>,
    apps: Arc<HashMap<String, AppTargetConfig>>,
    inbox: Arc<PokeInbox>,
    gossip: Arc<Mutex<Option<p2p_core::gossip::GossipHandle>>>,
    device_name: &str,
) -> Arc<webdesserts_mesh::api::ApiState> {
    let self_id = node.node_id();
    Arc::new(webdesserts_mesh::api::ApiState {
        node,
        allowlist,
        apps,
        inbox,
        gossip,
        pool: new_pool(),
        device_name: device_name.to_string(),
        self_id,
        relays: Vec::new(),
        pending_pairing: Arc::new(Mutex::new(None)),
        notes_health_url: "http://127.0.0.1:8082/health".to_string(),
        relay_listen: false,
    })
}

// ---------------------------------------------------------------- §6.1 config

#[tokio::test]
async fn config_dir_is_0700_file_is_0600_and_lock_is_exclusive() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!("wd-mesh-cfg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let paths = MeshPaths::at(&dir);
    paths.ensure_dir()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "mesh data dir must be 0700");
    }

    let cfg = MeshConfig::new("umbra");
    paths.save_config(&cfg)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&paths.config)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config.toml must be 0600");
    }

    let back = paths.load_config()?;
    assert_eq!(back.device_name, "umbra");
    assert_eq!(back.listen_addr, "127.0.0.1:4620");
    assert!(!back.relay_listen, "relay_listen must default to false");

    // `base_url` targets parse and resolve their port.
    let mut with_url = MeshConfig::new("umbra");
    with_url
        .apps
        .insert("agents".to_string(), AppTargetConfig::from_base_url("http://127.0.0.1:22091"));
    assert_eq!(with_url.apps["agents"].resolved_port()?, 22091);
    let text = with_url.to_toml()?;
    let reparsed = MeshConfig::from_toml(&text)?;
    assert_eq!(reparsed.apps["agents"].resolved_port()?, 22091);

    let lock = p2p_core::daemon_lock::DaemonLock::acquire_at(&paths.lock)
        .map_err(|e| anyhow::anyhow!("first lock: {e}"))?;
    assert!(
        p2p_core::daemon_lock::DaemonLock::acquire_at(&paths.lock).is_err(),
        "a second daemon lock must fail"
    );
    lock.release().map_err(|e| anyhow::anyhow!("release: {e}"))?;

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ------------------------------------------------------------- §6.2 CSRF guard

#[tokio::test]
async fn csrf_guard_refuses_origin_and_non_loopback_host() -> anyhow::Result<()> {
    let allowlist = file_allowlist("csrf");
    let node = P2pNode::builder(seed(9), &[], allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;
    let state = api_state(
        Arc::new(node),
        allowlist,
        Arc::new(HashMap::new()),
        Arc::new(PokeInbox::new(8)),
        Arc::new(Mutex::new(None)),
        "umbra",
    );
    let port = spawn_api(state).await?;

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}/status");

    let ok = client.get(&base).send().await?;
    assert_eq!(ok.status().as_u16(), 200, "loopback request must pass");

    let origin = client
        .get(&base)
        .header("origin", "https://evil.example")
        .send()
        .await?;
    assert_eq!(origin.status().as_u16(), 403, "Origin must be refused");

    // reqwest rewrites a manual Host header, so send a raw HTTP/1.1 request.
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    sock.write_all(b"GET /status HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
        .await?;
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await?;
    let raw = String::from_utf8_lossy(&buf);
    assert!(
        raw.starts_with("HTTP/1.1 403"),
        "non-loopback Host must be refused, got: {}",
        raw.lines().next().unwrap_or_default()
    );

    Ok(())
}

// ------------------------------------------------------------ §6.3 E2E request

#[tokio::test]
async fn e2e_request_resolves_device_name_and_rewrites_host() -> anyhow::Result<()> {
    let app_port = spawn_mock_app().await?;

    let mut apps = HashMap::new();
    apps.insert("feeds".to_string(), AppTargetConfig::new(app_port));
    apps.insert("notes".to_string(), AppTargetConfig::read_only(app_port));
    let apps = Arc::new(apps);

    // umbra owns the apps + proxy handler + API server; rhea is the client.
    // umbra'"'"'s allowlist names rhea "rhea", so the injected device name is
    // "rhea" (spec §6.3).
    let umbra_allowlist = file_allowlist("umbra-e2e");
    let umbra = P2pNode::builder(seed(1), &[], umbra_allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .with_protocol(
            HTTP_PROXY_ALPN,
            webdesserts_mesh::proxy::MeshHttpProxyHandler::new(umbra_allowlist.clone(), apps.clone()),
        )
        .build()
        .await?;

    let rhea_allowlist = file_allowlist("rhea-e2e");
    let rhea = P2pNode::builder(seed(2), &[], rhea_allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;
    // rhea is the CLIENT (it runs the API server), so rhea needs umbra'"'"'s
    // address; umbra is the SERVER (it owns the proxy handler + apps).
    seed_lookup(&rhea, &umbra)?;

    umbra_allowlist.add_peer(rhea.node_id(), "rhea").await?;
    rhea_allowlist.add_peer(umbra.node_id(), "umbra").await?;

    let umbra_id = umbra.node_id();
    let rhea_id = rhea.node_id();
    let rhea_node = Arc::new(rhea);
    let state = api_state(
        rhea_node.clone(),
        rhea_allowlist,
        apps.clone(),
        Arc::new(PokeInbox::new(8)),
        Arc::new(Mutex::new(None)),
        "umbra",
    );
    let api_port = spawn_api(state).await?;

    // `:target` is the device name "rhea"; the query string must survive.
    let url = format!("http://127.0.0.1:{api_port}/peer/umbra/app/feeds/api/test?foo=bar");
    let resp = reqwest::Client::new()
        .post(&url)
        .header("x-mesh-peer-id", "spoofed")
        .header("x-mesh-device-name", "spoofed")
        .header("x-mesh-relationship", "spoofed")
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().await?;

    assert!(
        text.contains(&format!("peer={}", rhea_id)),
        "peer id must be authoritative, got {text}"
    );
    assert!(text.contains("device=rhea"), "device name must be rhea, got {text}");
    assert!(text.contains("rel=self"), "relationship must be self, got {text}");
    assert!(
        text.contains(&format!("host=127.0.0.1:{app_port}")),
        "Host must be rewritten to the local app, got {text}"
    );
    assert!(text.contains("uri=/api/test?foo=bar"), "query must survive, got {text}");
    assert!(!text.contains("spoofed"), "spoofed headers must be stripped: {text}");

    // Unknown device name -> 404.
    let unknown = format!("http://127.0.0.1:{api_port}/peer/nobody/app/feeds/health");
    let nf = reqwest::Client::new().get(&unknown).send().await?;
    assert_eq!(nf.status().as_u16(), 404, "unknown target must 404");

    // SSE / Upgrade -> 400.
    let pool = new_pool();
    let sse = ProxyRequest {
        app_id: "feeds".to_string(),
        method: "GET".to_string(),
        path: "/events".to_string(),
        headers: vec![("accept".to_string(), "text/event-stream".to_string())],
        body_len: 0,
    };
    let (sse_resp, _) = forward_with_body(&pool, rhea_node.as_ref(), umbra_id, sse, Vec::new()).await?;
    assert_eq!(sse_resp.status, 400, "SSE must be refused");

    let upgrade = ProxyRequest {
        app_id: "feeds".to_string(),
        method: "GET".to_string(),
        path: "/ws".to_string(),
        headers: vec![("upgrade".to_string(), "websocket".to_string())],
        body_len: 0,
    };
    let (up_resp, _) = forward_with_body(&pool, rhea_node.as_ref(), umbra_id, upgrade, Vec::new()).await?;
    assert_eq!(up_resp.status, 400, "Upgrade must be refused");

    // notes: GET ok, POST -> 403 (read-only app).
    let notes_get = ProxyRequest {
        app_id: "notes".to_string(),
        method: "GET".to_string(),
        path: "/health".to_string(),
        headers: Vec::new(),
        body_len: 0,
    };
    let (ng, _) = forward_with_body(&pool, rhea_node.as_ref(), umbra_id, notes_get, Vec::new()).await?;
    assert_eq!(ng.status, 200, "notes GET must pass");

    let notes_post = ProxyRequest {
        app_id: "notes".to_string(),
        method: "POST".to_string(),
        path: "/mcp".to_string(),
        headers: Vec::new(),
        body_len: 2,
    };
    let (np, _) = forward_with_body(&pool, rhea_node.as_ref(), umbra_id, notes_post, b"{}".to_vec()).await?;
    assert_eq!(np.status, 403, "notes POST must be refused");

    Ok(())
}

// ------------------------------------------------------- §6.4 C1(a) revocation

#[tokio::test]
async fn revoked_peer_is_refused_on_next_bi_stream_of_same_connection() -> anyhow::Result<()> {
    let app_port = spawn_mock_app().await?;
    let mut apps = HashMap::new();
    apps.insert("feeds".to_string(), AppTargetConfig::new(app_port));
    let apps = Arc::new(apps);

    let rhea_allowlist = file_allowlist("rhea-revoke");
    let rhea = P2pNode::builder(seed(4), &[], rhea_allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .with_protocol(
            HTTP_PROXY_ALPN,
            webdesserts_mesh::proxy::MeshHttpProxyHandler::new(rhea_allowlist.clone(), apps.clone()),
        )
        .build()
        .await?;

    let umbra_allowlist = file_allowlist("umbra-revoke");
    let umbra = P2pNode::builder(seed(3), &[], umbra_allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;
    seed_lookup(&umbra, &rhea)?;

    umbra_allowlist.add_peer(rhea.node_id(), "rhea").await?;
    rhea_allowlist.add_peer(umbra.node_id(), "umbra").await?;

    let conn = umbra
        .connect(&PeerAddr::new(rhea.node_id()), HTTP_PROXY_ALPN)
        .await?;

    let req = ProxyRequest {
        app_id: "feeds".to_string(),
        method: "GET".to_string(),
        path: "/health".to_string(),
        headers: Vec::new(),
        body_len: 0,
    };

    // First bi-stream: allowed.
    let (mut send, mut recv) = conn.open_bi().await?;
    write_length_prefixed(&mut send, &serde_json::to_vec(&req)?).await?;
    let _ = send.finish();
    let meta = read_length_prefixed(&mut recv).await?;
    let resp: webdesserts_mesh::proxy::ProxyResponse = serde_json::from_slice(&meta)?;
    assert_eq!(resp.status, 200, "paired peer must be served");

    // Revoke on the server side.
    rhea_allowlist.remove_peer(&umbra.node_id()).await?;

    // Second bi-stream on the SAME connection must be refused (C1(a)).
    let (mut send2, _recv2) = conn.open_bi().await?;
    let _ = write_length_prefixed(&mut send2, &serde_json::to_vec(&req)?).await;

    match conn.closed().await {
        ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code, VarInt::from_u32(1), "close code must be 1");
            assert_eq!(
                close.reason.as_ref(),
                b"not in allowlist".as_slice(),
                "close reason must be not in allowlist"
            );
        }
        other => panic!("expected ApplicationClosed code 1, got {other:?}"),
    }

    Ok(())
}

// ------------------------------------------------------- §6.5 poke + long-poll

#[tokio::test]
async fn poke_broadcast_wakes_peer_long_poll() -> anyhow::Result<()> {
    let rhea_allowlist = file_allowlist("rhea-poke");
    let rhea = P2pNode::builder(seed(6), &[], rhea_allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;

    let umbra_allowlist = file_allowlist("umbra-poke");
    let umbra = P2pNode::builder(seed(5), &[], umbra_allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;
    seed_lookup(&umbra, &rhea)?;

    umbra_allowlist.add_peer(rhea.node_id(), "rhea").await?;
    rhea_allowlist.add_peer(umbra.node_id(), "umbra").await?;

    let topic = poke_topic();
    let mut rhea_sub = rhea.subscribe(topic, vec![umbra.node_id()]).await?;
    let mut umbra_sub = umbra.subscribe(topic, vec![rhea.node_id()]).await?;

    let up = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            match umbra_sub.recv().await {
                Some(p2p_core::gossip::GossipEvent::NeighborUp(_)) => break true,
                Some(_) => continue,
                None => break false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(up, "gossip neighbor must come up");

    let inbox = Arc::new(PokeInbox::new(512));
    let wire = MeshPokeWire {
        app_id: "feeds".to_string(),
        topic: "feeds".to_string(),
        cursor: "m658".to_string(),
        sender_peer_id: umbra.node_id().to_string(),
        timestamp_ms: 1,
        nonce: 42,
    };
    umbra_sub
        .broadcast(bytes::Bytes::from(serde_json::to_vec(&wire)?))
        .await?;

    let got = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if let Some(p2p_core::gossip::GossipEvent::Data { bytes, .. }) = rhea_sub.recv().await {
                if let Ok(w) = serde_json::from_slice::<MeshPokeWire>(&bytes) {
                    // Receiver-local seq + allowlist-resolved from_device.
                    inbox.push(w, Some("umbra".to_string()));
                    break;
                }
            }
        }
        inbox.since(0, Some("feeds"))
    })
    .await?;

    assert_eq!(got.len(), 1, "rhea must receive exactly one poke");
    assert_eq!(got[0].seq, 1, "seq is receiver-local and starts at 1");
    assert_eq!(got[0].cursor, "m658");
    assert_eq!(got[0].sender_peer_id, umbra.node_id().to_string());
    assert_eq!(got[0].from_device.as_deref(), Some("umbra"));

    // A second poke from a different sender must get seq 2, not collide.
    let seq2 = inbox.push(
        MeshPokeWire {
            app_id: "feeds".to_string(),
            topic: "feeds".to_string(),
            cursor: "m659".to_string(),
            sender_peer_id: "unknown-peer".to_string(),
            timestamp_ms: 2,
            nonce: 43,
        },
        None,
    );
    assert_eq!(seq2, 2, "receiver-local seq must be monotonic");
    let all = inbox.since(1, None);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].from_device, None, "unknown sender must not claim a name");

    Ok(())
}

// ------------------------------------------------- §6.6 two concurrent pollers

#[tokio::test]
async fn two_concurrent_pollers_both_wake_on_one_poke() -> anyhow::Result<()> {
    let allowlist = file_allowlist("pollers");
    let node = P2pNode::builder(seed(7), &[], allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;
    let inbox = Arc::new(PokeInbox::new(512));
    let state = api_state(
        Arc::new(node),
        allowlist,
        Arc::new(HashMap::new()),
        inbox.clone(),
        Arc::new(Mutex::new(None)),
        "umbra",
    );
    let port = spawn_api(state).await?;

    let url = format!("http://127.0.0.1:{port}/pokes?appId=feeds&since=0&timeout_ms=5000");
    let client = reqwest::Client::new();

    // Two pollers start before the poke arrives.
    let a = tokio::spawn({
        let c = client.clone();
        let u = url.clone();
        async move { c.get(&u).send().await }
    });
    let b = tokio::spawn({
        let c = client.clone();
        let u = url.clone();
        async move { c.get(&u).send().await }
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    inbox.push(
        MeshPokeWire {
            app_id: "feeds".to_string(),
            topic: "feeds".to_string(),
            cursor: "m700".to_string(),
            sender_peer_id: "peer".to_string(),
            timestamp_ms: 3,
            nonce: 44,
        },
        Some("umbra".to_string()),
    );

    let ra = tokio::time::timeout(std::time::Duration::from_secs(10), a).await??;
    let rb = tokio::time::timeout(std::time::Duration::from_secs(10), b).await??;
    let ja: webdesserts_mesh::api::PokesResp = ra?.json().await?;
    let jb: webdesserts_mesh::api::PokesResp = rb?.json().await?;

    assert_eq!(ja.pokes.len(), 1, "poller A must wake with the poke");
    assert_eq!(jb.pokes.len(), 1, "poller B must wake with the poke");
    assert_eq!(ja.pokes[0].seq, 1);
    assert_eq!(jb.pokes[0].seq, 1);
    assert_eq!(ja.epoch, jb.epoch, "both pollers see the same epoch");
    assert!(!ja.truncated && !jb.truncated, "a live cursor is not truncated");

    Ok(())
}

// ------------------------------------------ §6.7 Phase 3 acceptance (Part A)

#[test]
fn proxy_strips_caller_identity_headers() {
    for h in [
        "x-auth-user",
        "x-auth-actor",
        "x-autonomy-agent",
        "x-mesh-peer-id",
        "host",
        "connection",
        "transfer-encoding",
    ] {
        assert!(should_strip_header(h), "{h} must be stripped");
    }
    for h in ["content-type", "accept", "x-custom", "authorization"] {
        assert!(!should_strip_header(h), "{h} must pass through");
    }
}

fn wire(cursor: &str) -> MeshPokeWire {
    MeshPokeWire {
        app_id: "feeds".to_string(),
        topic: "feeds".to_string(),
        cursor: cursor.to_string(),
        sender_peer_id: "peer".to_string(),
        timestamp_ms: 0,
        nonce: 0,
    }
}

#[test]
fn poke_inbox_reports_epoch_mismatch_ahead_and_eviction() {
    let inbox = PokeInbox::with_epoch(2, 7);
    inbox.push(wire("m1"), None);
    inbox.push(wire("m2"), None);

    // A live cursor is not truncated and reads from `since`.
    let (pokes, truncated, eff) = inbox.read_since(0, Some(7), None);
    assert_eq!(pokes.len(), 2);
    assert!(!truncated);
    assert_eq!(eff, 0);

    // Epoch mismatch (daemon restart) resets to 0 and flags truncation.
    let (pokes, truncated, eff) = inbox.read_since(2, Some(99), None);
    assert_eq!(pokes.len(), 2, "a restart must deliver every buffered poke");
    assert!(truncated);
    assert_eq!(eff, 0);

    // A cursor ahead of the latest seq is unusable.
    let (_, truncated, _) = inbox.read_since(99, Some(7), None);
    assert!(truncated);

    // Ring-buffer eviction: cap 2, a third push evicts seq 1.
    inbox.push(wire("m3"), None);
    let (pokes, truncated, eff) = inbox.read_since(1, Some(7), None);
    assert!(truncated, "a cursor at/below the evicted seq is truncated");
    assert_eq!(eff, 0);
    assert_eq!(pokes.len(), 2);
    assert_eq!(pokes[0].cursor, "m2");
}

#[tokio::test]
async fn unique_peer_names_suffix_on_clash_and_refuse_tombstones() -> anyhow::Result<()> {
    let allowlist = file_allowlist("unique-names");
    let a = p2p_core::PeerId::from_bytes(seed(11));
    let b = p2p_core::PeerId::from_bytes(seed(12));

    let n1 = webdesserts_mesh::add_or_update_peer_unique(&allowlist, a, "rhea").await?;
    assert_eq!(n1, "rhea");
    let n2 = webdesserts_mesh::add_or_update_peer_unique(&allowlist, b, "RHEA").await?;
    assert!(
        n2.starts_with("RHEA-"),
        "a case-insensitive clash must be suffixed: {n2}"
    );

    allowlist.remove_peer(&a).await?;
    let err = webdesserts_mesh::add_or_update_peer_unique(&allowlist, a, "rhea")
        .await
        .expect_err("a tombstoned peer must be refused");
    assert!(
        matches!(err, p2p_core::allowlist::AllowlistError::PeerRevoked(p) if p == a),
        "expected PeerRevoked, got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn status_reports_phase3_fields() -> anyhow::Result<()> {
    let allowlist = file_allowlist("status-p3");
    let node = P2pNode::builder(seed(13), &[], allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;
    let inbox = Arc::new(PokeInbox::with_epoch(512, 42));
    let state = api_state(
        Arc::new(node),
        allowlist,
        Arc::new(HashMap::new()),
        inbox,
        Arc::new(Mutex::new(None)),
        "umbra",
    );
    let port = spawn_api(state).await?;
    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/status"))
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 200);
    let j: serde_json::Value = resp.json().await?;
    assert_eq!(j["relay_listen"], false);
    assert_eq!(j["poke_epoch"], 42);
    assert_eq!(j["latest_poke_seq"], 0);
    assert!(
        j["notes_sync_healthy"].is_boolean(),
        "notes_sync_healthy must be reported"
    );
    Ok(())
}

#[tokio::test]
async fn pair_code_arms_a_single_use_code() -> anyhow::Result<()> {
    let allowlist = file_allowlist("pair-code");
    let node = P2pNode::builder(seed(14), &[], allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;
    let state = api_state(
        Arc::new(node),
        allowlist,
        Arc::new(HashMap::new()),
        Arc::new(PokeInbox::new(512)),
        Arc::new(Mutex::new(None)),
        "umbra",
    );
    let port = spawn_api(state.clone()).await?;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/pair/code"))
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 200);
    let j: serde_json::Value = resp.json().await?;
    let code = j["code"].as_str().expect("code must be a string").to_string();
    assert_eq!(code.len(), 6, "code must be 6 digits");
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(j["expires_in_secs"], 300);
    let armed = state.pending_pairing.lock().await.clone();
    assert_eq!(
        armed.map(|p| p.code),
        Some(code),
        "the armed code must be stored for the inbound pump"
    );
    Ok(())
}

#[tokio::test]
async fn pair_refuses_revoked_peer_with_conflict() -> anyhow::Result<()> {
    let allowlist = file_allowlist("pair-revoked");
    let node = P2pNode::builder(seed(15), &[], allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;
    let peer = p2p_core::PeerId::from_bytes(seed(16));
    allowlist.add_peer(peer, "rhea").await?;
    allowlist.remove_peer(&peer).await?;
    let state = api_state(
        Arc::new(node),
        allowlist,
        Arc::new(HashMap::new()),
        Arc::new(PokeInbox::new(512)),
        Arc::new(Mutex::new(None)),
        "umbra",
    );
    let port = spawn_api(state).await?;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/pair"))
        .json(&serde_json::json!({ "peer": peer.to_string(), "code": "123456" }))
        .send()
        .await?;
    assert_eq!(
        resp.status().as_u16(),
        409,
        "a revoked peer must be refused before dialing"
    );
    Ok(())
}

#[tokio::test]
async fn two_node_pairing_populates_both_allowlists_with_real_names() -> anyhow::Result<()> {
    let tag = std::process::id();
    let umbra_dir = std::env::temp_dir().join(format!("wd-mesh-pair-umbra-{tag}"));
    let rhea_dir = std::env::temp_dir().join(format!("wd-mesh-pair-rhea-{tag}"));
    let _ = std::fs::remove_dir_all(&umbra_dir);
    let _ = std::fs::remove_dir_all(&rhea_dir);

    let umbra = Arc::new(MeshDaemon::start(MeshPaths::at(&umbra_dir), MeshConfig::new("umbra")).await?);
    let rhea = Arc::new(MeshDaemon::start(MeshPaths::at(&rhea_dir), MeshConfig::new("rhea")).await?);
    seed_lookup(rhea.node.as_ref(), umbra.node.as_ref())?;

    let umbra_port = spawn_api(umbra.api_state()).await?;
    let rhea_port = spawn_api(rhea.api_state()).await?;
    let client = reqwest::Client::new();

    // Acceptor arms a single-use code; initiator dials with it.
    let armed: serde_json::Value = client
        .post(format!("http://127.0.0.1:{umbra_port}/pair/code"))
        .send()
        .await?
        .json()
        .await?;
    let code = armed["code"].as_str().expect("armed code").to_string();

    let res: serde_json::Value = client
        .post(format!("http://127.0.0.1:{rhea_port}/pair"))
        .json(&serde_json::json!({
            "peer": umbra.node.node_id().to_string(),
            "code": code,
        }))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(res["success"], true, "pairing must succeed: {res}");

    // Both sides record the peer'"'"'s real device name from the handshake:
    // the initiator captures `challenge.device_name`, the acceptor uses the
    // inbound hello'"'"'s `device_name`.
    let umbra_peers = umbra.allowlist.list_peers().await?;
    let rhea_peers = rhea.allowlist.list_peers().await?;
    assert_eq!(umbra_peers.len(), 1, "umbra must record exactly one peer");
    assert_eq!(rhea_peers.len(), 1, "rhea must record exactly one peer");
    assert_eq!(umbra_peers[0].device_name, "rhea");
    assert_eq!(rhea_peers[0].device_name, "umbra");
    assert_eq!(umbra_peers[0].node_id, rhea.node.node_id());
    assert_eq!(rhea_peers[0].node_id, umbra.node.node_id());

    // The armed code was consumed, so a second inbound attempt has nothing to
    // approve (single-use, #m550 B2).
    assert!(
        umbra.pending_pairing.lock().await.is_none(),
        "the armed code must be consumed by the first pairing"
    );

    // Start poke gossip on both nodes and verify POST /poke -> GET /pokes over the wire.
    umbra.start_poke_gossip().await?;
    rhea.start_poke_gossip().await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let poke_resp = client
        .post(format!("http://127.0.0.1:{umbra_port}/poke"))
        .json(&serde_json::json!({
            "appId": "feeds",
            "topic": "autonomy",
            "cursor": "m558",
        }))
        .send()
        .await?;
    assert!(poke_resp.status().is_success());
    let pokes: webdesserts_mesh::api::PokesResp = client
        .get(format!("http://127.0.0.1:{rhea_port}/pokes?since=0&timeout_ms=3000"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(pokes.pokes.len(), 1, "rhea must receive umbra's poke via POST /poke");
    assert_eq!(pokes.pokes[0].cursor, "m558");
    assert_eq!(pokes.pokes[0].from_device.as_deref(), Some("umbra"));
    Ok(())
}
