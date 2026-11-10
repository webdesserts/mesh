//! Phase 4 acceptance tests (spec §3.2): signed membership log, permission
//! broker, register.sock app bridge.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{OriginalUri, State as AxState};
use axum::http::HeaderMap;
use axum::routing::any;
use iroh::address_lookup::memory::MemoryLookup;
use p2p_core::allowlist::{AllowlistStorage, FileAllowlistStorage};
use p2p_core::membership::Relationship;
use p2p_core::node::P2pNode;
use webdesserts_mesh::MeshDaemon;
use webdesserts_mesh::config::{AppTargetConfig, MeshConfig, MeshPaths};
use webdesserts_mesh::proxy::{HTTP_PROXY_ALPN, ProxyRequest, forward_with_body, new_pool};
use webdesserts_mesh::register::short_test_dir;

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

fn seed_lookup(node: &P2pNode, peer: &P2pNode) -> anyhow::Result<()> {
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(peer.endpoint_for_test().addr());
    node.endpoint_for_test().address_lookup()?.add(lookup);
    Ok(())
}

async fn spawn_api(state: Arc<webdesserts_mesh::api::ApiState>) -> anyhow::Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let router = webdesserts_mesh::api::router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(port)
}

async fn spawn_tcp_api(state: Arc<webdesserts_mesh::api::ApiState>) -> anyhow::Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let router = webdesserts_mesh::api::tcp_router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(port)
}

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
        "peer={} mesh={} device={} rel={} uri={}",
        get("x-mesh-peer-id"),
        get("x-mesh-mesh-id"),
        get("x-mesh-device-name"),
        get("x-mesh-relationship"),
        uri
    )
}

async fn spawn_mock_app() -> anyhow::Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route("/{*path}", any(mock_app)).with_state(());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

/// Start a daemon in a short temp dir (macOS `sun_path` is 104 bytes).
async fn daemon(tag: &str, name: &str) -> anyhow::Result<Arc<MeshDaemon>> {
    let dir = short_test_dir(tag);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(Arc::new(
        MeshDaemon::start(MeshPaths::at(&dir), MeshConfig::new(name)).await?,
    ))
}

/// Arm a code on `acceptor` and dial it from `initiator`.
async fn pair(
    acceptor: &Arc<MeshDaemon>,
    acceptor_port: u16,
    _initiator: &Arc<MeshDaemon>,
    initiator_port: u16,
) -> anyhow::Result<(u16, serde_json::Value)> {
    let client = reqwest::Client::new();
    let armed: serde_json::Value = client
        .post(format!("http://127.0.0.1:{acceptor_port}/pair/code"))
        .send()
        .await?
        .json()
        .await?;
    let code = armed["code"].as_str().expect("armed code").to_string();
    let resp = client
        .post(format!("http://127.0.0.1:{initiator_port}/pair"))
        .json(&serde_json::json!({
            "peer": acceptor.node.node_id().to_string(),
            "code": code,
        }))
        .send()
        .await?;
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
    Ok((status, body))
}

async fn membership(port: u16) -> anyhow::Result<serde_json::Value> {
    Ok(reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/membership"))
        .send()
        .await?
        .json()
        .await?)
}

// ------------------------------------------------- §3.2 #1 pair convergence

#[tokio::test]
async fn pair_two_nodes_converges_on_single_mesh_id_and_signed_log() -> anyhow::Result<()> {
    let umbra = daemon("p4-umbra", "umbra").await?;
    let rhea = daemon("p4-rhea", "rhea").await?;
    seed_lookup(rhea.node.as_ref(), umbra.node.as_ref())?;

    let umbra_port = spawn_api(umbra.api_state()).await?;
    let rhea_port = spawn_api(rhea.api_state()).await?;

    let (status, body) = pair(&umbra, umbra_port, &rhea, rhea_port).await?;
    assert_eq!(status, 200, "pairing must succeed: {body}");

    let umbra_m = membership(umbra_port).await?;
    let rhea_m = membership(rhea_port).await?;
    assert_eq!(
        umbra_m["mesh_id"], rhea_m["mesh_id"],
        "both nodes must converge on one mesh_id"
    );
    assert_eq!(umbra_m["entries_count"], 2, "acceptor log holds genesis + Add");
    assert_eq!(rhea_m["entries_count"], 2, "initiator adopts the canonical log");
    let active = umbra_m["active_peers"].as_array().expect("active_peers");
    assert_eq!(active.len(), 2, "both peers active on the acceptor");
    assert!(
        active.iter().any(|p| p["device_name"] == "rhea"),
        "the joiner is recorded under its real device name: {umbra_m}"
    );

    // A third solo node joining B adopts A/B's mesh and converges to 3 entries.
    let charon = daemon("p4-charon", "charon").await?;
    seed_lookup(charon.node.as_ref(), rhea.node.as_ref())?;
    let charon_port = spawn_api(charon.api_state()).await?;
    let (status, body) = pair(&rhea, rhea_port, &charon, charon_port).await?;
    assert_eq!(status, 200, "third node must join: {body}");

    // umbra also catches up from rhea so all three nodes converge on 3 entries.
    seed_lookup(umbra.node.as_ref(), rhea.node.as_ref())?;
    webdesserts_mesh::membership_sync::pull_anti_entropy(
        umbra.node.as_ref(),
        rhea.node.node_id(),
        &umbra.membership,
    )
    .await?;
    let umbra_m = membership(umbra_port).await?;
    let rhea_m = membership(rhea_port).await?;
    let charon_m = membership(charon_port).await?;
    assert_eq!(
        charon_m["mesh_id"], umbra_m["mesh_id"],
        "the joiner adopts the sponsor's mesh_id"
    );
    assert_eq!(umbra_m["entries_count"], 3, "umbra converges on all three entries");
    assert_eq!(rhea_m["entries_count"], 3, "rhea holds all three entries");
    assert_eq!(charon_m["entries_count"], 3, "charon holds all three entries");

    // Re-pairing a revoked key is refused with 409 (S1c sticky revocation).
    let charon_id = charon.node.node_id();
    let removed = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{umbra_port}/membership/remove"))
        .json(&serde_json::json!({ "peer": charon_id.to_string() }))
        .send()
        .await?;
    assert_eq!(removed.status().as_u16(), 200, "remove must succeed");
    let after = membership(umbra_port).await?;
    assert!(
        after["revoked_peers"]
            .as_array()
            .expect("revoked")
            .iter()
            .any(|p| p["peer_id"] == charon_id.to_string()),
        "the removed peer must be revoked: {after}"
    );
    let (status, body) = pair(&umbra, umbra_port, &charon, charon_port).await?;
    assert_eq!(status, 409, "a revoked key must not re-pair: {body}");
    Ok(())
}

// ------------------------------------- §3.2 #2 revoke teardown (proxy + pool)

#[tokio::test]
async fn post_membership_remove_revokes_peer_and_tears_down_gossip_and_proxy(
) -> anyhow::Result<()> {
    let umbra = daemon("p4-rev-umbra", "umbra").await?;
    let rhea = daemon("p4-rev-rhea", "rhea").await?;
    seed_lookup(rhea.node.as_ref(), umbra.node.as_ref())?;
    let umbra_port = spawn_api(umbra.api_state()).await?;
    let rhea_port = spawn_api(rhea.api_state()).await?;
    let (status, body) = pair(&umbra, umbra_port, &rhea, rhea_port).await?;
    assert_eq!(status, 200, "pairing must succeed: {body}");

    let rhea_id = rhea.node.node_id();
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{umbra_port}/membership/remove"))
        .json(&serde_json::json!({ "peer": "rhea" }))
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 200, "remove by device name must work");

    // The projection is the sole writer: the allowlist no longer admits rhea.
    let peers = umbra.allowlist.list_peers().await?;
    assert!(
        peers.iter().all(|p| p.node_id != rhea_id || p.removed),
        "a revoked peer must not stay admitted: {peers:?}"
    );
    assert!(
        !umbra.membership.is_active(&rhea_id).await,
        "membership must report the peer inactive"
    );
    assert!(
        umbra.membership.revoked_peers().await.contains(&rhea_id),
        "membership must report the peer revoked"
    );

    // A request from the revoked peer is refused (403 frame or closed stream).
    let req = ProxyRequest {
        app_id: "feeds".to_string(),
        method: "GET".to_string(),
        path: "/health".to_string(),
        headers: Vec::new(),
        body_len: 0,
    };
    let outcome = forward_with_body(&new_pool(), rhea.node.as_ref(), umbra.node.node_id(), req, Vec::new()).await;
    let refused = match outcome {
        Err(_) => true,
        Ok((resp, _)) => resp.status == 403 || resp.status == 502,
    };
    assert!(refused, "a revoked peer must not be served by the proxy");

    // Local files are untouched by a revocation.
    assert!(umbra.paths.membership.exists(), "membership.json must persist");
    Ok(())
}

// ------------------------------- §3.2 #3 anti-entropy catch-up on reconnect

#[tokio::test]
async fn offline_node_catches_up_membership_via_anti_entropy_on_reconnect() -> anyhow::Result<()> {
    let umbra = daemon("p4-ae-umbra", "umbra").await?;
    let rhea = daemon("p4-ae-rhea", "rhea").await?;
    seed_lookup(rhea.node.as_ref(), umbra.node.as_ref())?;
    let umbra_port = spawn_api(umbra.api_state()).await?;
    let rhea_port = spawn_api(rhea.api_state()).await?;
    let (status, body) = pair(&umbra, umbra_port, &rhea, rhea_port).await?;
    assert_eq!(status, 200, "pairing must succeed: {body}");

    // A third node joins rhea, so it knows rhea but not umbra's later Remove.
    let charon = daemon("p4-ae-charon", "charon").await?;
    seed_lookup(charon.node.as_ref(), rhea.node.as_ref())?;
    let charon_port = spawn_api(charon.api_state()).await?;
    let (status, body) = pair(&rhea, rhea_port, &charon, charon_port).await?;
    assert_eq!(status, 200, "third node must join: {body}");

    // charon also pairs with umbra, so umbra admits it for the anti-entropy pull.
    seed_lookup(charon.node.as_ref(), umbra.node.as_ref())?;
    let (status, body) = pair(&umbra, umbra_port, &charon, charon_port).await?;
    assert_eq!(status, 200, "charon must also pair with umbra: {body}");

    // umbra revokes rhea while charon is "offline" (it never sees the gossip).
    let rhea_id = rhea.node.node_id();
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{umbra_port}/membership/remove"))
        .json(&serde_json::json!({ "peer": rhea_id.to_string() }))
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        charon.membership.is_active(&rhea_id).await,
        "charon still believes rhea is active before catching up"
    );

    // On reconnect charon pulls the missing entries over ALPN_MEMBERSHIP.
    let revoked = webdesserts_mesh::membership_sync::pull_anti_entropy(
        charon.node.as_ref(),
        umbra.node.node_id(),
        &charon.membership,
    )
    .await?;
    assert!(
        revoked.contains(&rhea_id),
        "the anti-entropy pull must report the newly revoked peer: {revoked:?}"
    );
    assert!(
        !charon.membership.is_active(&rhea_id).await,
        "charon must drop rhea after catching up"
    );
    assert!(
        charon.membership.revoked_peers().await.contains(&rhea_id),
        "the Remove entry must be merged into charon's log"
    );
    Ok(())
}

// ------------------------------- §3.2 #4 re-genesis preserves data

#[tokio::test]
async fn re_genesis_after_mutual_removal_or_force_preserves_data() -> anyhow::Result<()> {
    let umbra = daemon("p4-gen-umbra", "umbra").await?;
    let rhea = daemon("p4-gen-rhea", "rhea").await?;
    seed_lookup(rhea.node.as_ref(), umbra.node.as_ref())?;
    let umbra_port = spawn_api(umbra.api_state()).await?;
    let rhea_port = spawn_api(rhea.api_state()).await?;
    let (status, body) = pair(&umbra, umbra_port, &rhea, rhea_port).await?;
    assert_eq!(status, 200, "pairing must succeed: {body}");
    let old_mesh = membership(umbra_port).await?["mesh_id"].clone();

    // An app file in the data dir must survive a re-genesis untouched.
    let marker = umbra.paths.dir.join("app-state-marker.txt");
    std::fs::write(&marker, b"keep me")?;

    // Without force, an active device is refused.
    let refused = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{umbra_port}/membership/genesis"))
        .json(&serde_json::json!({ "force": false }))
        .send()
        .await?;
    assert_eq!(refused.status().as_u16(), 409, "active device needs force=true");

    let forced = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{umbra_port}/membership/genesis"))
        .json(&serde_json::json!({ "force": true }))
        .send()
        .await?;
    assert_eq!(forced.status().as_u16(), 200, "force re-genesis must succeed");

    let fresh = membership(umbra_port).await?;
    assert_ne!(fresh["mesh_id"], old_mesh, "re-genesis mints a new mesh_id");
    assert_eq!(fresh["entries_count"], 1, "a fresh log holds only the genesis");
    assert_eq!(
        fresh["active_peers"].as_array().expect("active").len(),
        1,
        "only the local device is active after re-genesis"
    );
    assert!(
        umbra.allowlist.list_peers().await?.is_empty(),
        "the projection clears the allowlist"
    );
    assert_eq!(
        std::fs::read_to_string(&marker)?,
        "keep me",
        "app data must survive re-genesis"
    );
    Ok(())
}

// --------------------------- §3.2 #6 register.sock token minting & hijack

fn http_over_uds_blocking(path: &std::path::Path, body: &str) -> anyhow::Result<(u16, String)> {
    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(path)?;
    let req = format!(
        "POST /register HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(req.as_bytes())?;
    let mut out = String::new();
    stream.read_to_string(&mut out)?;
    let status = out
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Ok((status, out))
}

/// The UDS round-trip is blocking, so it must run off the async runtime or the
/// single-threaded test runtime deadlocks against the serve_uds task.
async fn http_over_uds(path: &std::path::Path, body: &str) -> anyhow::Result<(u16, String)> {
    let path = path.to_path_buf();
    let body = body.to_string();
    tokio::task::spawn_blocking(move || http_over_uds_blocking(&path, &body)).await?
}

#[tokio::test]
async fn register_sock_mints_token_enforces_bearer_and_blocks_hijack() -> anyhow::Result<()> {
    let umbra = daemon("p4-reg-umbra", "umbra").await?;
    umbra.start_poke_gossip().await?;
    let state = umbra.api_state();
    let sock = umbra.paths.register_sock.clone();
    let serve_state = state.clone();
    let sock_for_task = sock.clone();
    tokio::spawn(async move {
        let _ = webdesserts_mesh::api::serve_uds(serve_state, sock_for_task).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // A dynamic app registers over the 0600 socket and receives a token.
    let (status, out) = http_over_uds(
        &sock,
        r#"{"app_id":"dynapp","port":5099,"read_only":false,"allow_friends":false}"#,
    )
    .await?;
    assert_eq!(status, 200, "register.sock must approve: {out}");
    let token = out
        .split("\"token\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("a minted token")
        .to_string();
    assert_eq!(token.len(), 64, "token must be 32-byte hex");
    assert!(
        umbra.registrations.verify_token("dynapp", &token).await,
        "the minted token must verify"
    );

    // Re-registering without the current bearer is refused (409).
    let (status, out) = http_over_uds(
        &sock,
        r#"{"app_id":"dynapp","port":5099,"read_only":false,"allow_friends":false}"#,
    )
    .await?;
    assert_eq!(status, 409, "re-registration needs the current bearer: {out}");

    // A static app id and a claimed port are both refused.
    let static_apps: std::collections::BTreeMap<String, AppTargetConfig> =
        umbra.apps.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    assert!(
        umbra
            .registrations
            .register("dynapp", 5099, false, false, &static_apps, &[], None)
            .await
            .is_err(),
        "re-registration without a token must fail"
    );
    assert!(
        umbra
            .registrations
            .register("other", 5099, false, false, &static_apps, &[], None)
            .await
            .is_err(),
        "a port already claimed by another app must be refused"
    );

    // `POST /poke` for a dynamic app requires the bearer token.
    let port = spawn_api(state.clone()).await?;
    let client = reqwest::Client::new();
    let unauth = client
        .post(format!("http://127.0.0.1:{port}/poke"))
        .json(&serde_json::json!({"appId":"dynapp","topic":"t","cursor":"c"}))
        .send()
        .await?;
    assert_eq!(unauth.status().as_u16(), 401, "dynamic app poke needs a bearer");
    let auth = client
        .post(format!("http://127.0.0.1:{port}/poke"))
        .header("authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({"appId":"dynapp","topic":"t","cursor":"c"}))
        .send()
        .await?;
    assert_eq!(auth.status().as_u16(), 200, "a valid bearer must be accepted");

    // Mutating management routes over TCP require the admin token.
    let tcp_port = spawn_tcp_api(state.clone()).await?;
    let no_admin = client
        .post(format!("http://127.0.0.1:{tcp_port}/apps/register"))
        .json(&serde_json::json!({"app_id":"x","port":5098}))
        .send()
        .await?;
    assert_eq!(no_admin.status().as_u16(), 401, "TCP management needs admin.token");
    let admin = umbra.registrations.admin_token().to_string();
    let with_admin = client
        .post(format!("http://127.0.0.1:{tcp_port}/apps/register"))
        .header("authorization", format!("Bearer {admin}"))
        .json(&serde_json::json!({"app_id":"x","port":5098}))
        .send()
        .await?;
    assert_eq!(with_admin.status().as_u16(), 200, "admin.token must be accepted");
    Ok(())
}

// ------------------------------- §3.2 #7 idempotent retry without suffix

#[tokio::test]
async fn same_peer_retry_is_idempotent_without_suffix() -> anyhow::Result<()> {
    let path = std::env::temp_dir().join(format!("wd-mesh-idem-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let allow = Arc::new(FileAllowlistStorage::at_path(path));
    let peer = p2p_core::PeerId::from_bytes(seed(21));
    let first = webdesserts_mesh::add_or_update_peer_unique(&allow, peer, "rhea").await?;
    assert_eq!(first, "rhea", "the first registration keeps the name");
    let second = webdesserts_mesh::add_or_update_peer_unique(&allow, peer, "rhea").await?;
    assert_eq!(second, "rhea", "a retry must not gain a -2 suffix");
    assert_eq!(allow.list_peers().await?.len(), 1, "a retry must not duplicate");
    Ok(())
}

// ------------------- §3.2 #5 permission broker: mesh_id + friend isolation

#[tokio::test]
async fn permission_broker_injects_mesh_id_and_blocks_friends_by_default() -> anyhow::Result<()> {
    let app_port = spawn_mock_app().await?;

    let mut apps = HashMap::new();
    apps.insert("open".to_string(), AppTargetConfig::new(app_port));
    let mut friends_ok = AppTargetConfig::new(app_port);
    friends_ok.allow_friends = true;
    apps.insert("friends".to_string(), friends_ok);
    let apps = Arc::new(apps);

    let umbra_allowlist = Arc::new(FileAllowlistStorage::at_path(
        std::env::temp_dir().join(format!("wd-mesh-pb-umbra-{}.json", std::process::id())),
    ));
    let umbra_membership = {
        let dir = short_test_dir("p4-pb-mem");
        let paths = MeshPaths::at(&dir);
        paths.ensure_dir()?;
        let identity = Arc::new(
            p2p_core::identity::IdentityKey::load_or_generate_at(&paths.key).await?,
        );
        let allow = Arc::new(FileAllowlistStorage::at_path(dir.join("allowlist.json")));
        Arc::new(
            webdesserts_mesh::membership_store::MembershipStore::load_or_init(
                identity,
                paths,
                allow,
                "umbra".to_string(),
            )
            .await?,
        )
    };
    let umbra_regs = {
        let dir = short_test_dir("p4-pb-regs");
        let paths = MeshPaths::at(&dir);
        paths.ensure_dir()?;
        Arc::new(webdesserts_mesh::register::RegistrationStore::load_or_init(paths).await?)
    };

    let umbra = P2pNode::builder(seed(31), &[], umbra_allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .with_protocol(
            HTTP_PROXY_ALPN,
            webdesserts_mesh::proxy::MeshHttpProxyHandler::new(
                umbra_allowlist.clone(),
                apps.clone(),
                umbra_membership.clone(),
                umbra_regs.clone(),
            ),
        )
        .build()
        .await?;

    let rhea_allowlist = Arc::new(FileAllowlistStorage::at_path(
        std::env::temp_dir().join(format!("wd-mesh-pb-rhea-{}.json", std::process::id())),
    ));
    let rhea = P2pNode::builder(seed(32), &[], rhea_allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;
    seed_lookup(&rhea, &umbra)?;

    // rhea is a FRIEND of umbra (not a self device).
    umbra_allowlist.add_peer(rhea.node_id(), "rhea").await?;
    rhea_allowlist.add_peer(umbra.node_id(), "umbra").await?;
    let add = umbra_membership
        .sign_add(rhea.node_id(), "rhea", Relationship::Friend)
        .await?;
    umbra_membership.append_entry(add).await?;

    let umbra_id = umbra.node_id();
    let rhea_id = rhea.node_id();
    let mesh_id = umbra_membership.mesh_id().await;
    let pool = new_pool();

    // A friend is refused on an app that does not allow friends.
    let blocked = ProxyRequest {
        app_id: "open".to_string(),
        method: "GET".to_string(),
        path: "/health".to_string(),
        headers: Vec::new(),
        body_len: 0,
    };
    let (resp, _) = forward_with_body(&pool, &rhea, umbra_id, blocked, Vec::new()).await?;
    assert_eq!(resp.status, 403, "a friend must be blocked by default");

    // ... and served on an app that opts in, with authoritative headers.
    let allowed = ProxyRequest {
        app_id: "friends".to_string(),
        method: "GET".to_string(),
        path: "/hello".to_string(),
        headers: vec![
            ("x-mesh-peer-id".to_string(), "spoofed".to_string()),
            ("x-mesh-mesh-id".to_string(), "spoofed".to_string()),
            ("x-mesh-relationship".to_string(), "spoofed".to_string()),
            ("x-mesh-device-name".to_string(), "spoofed".to_string()),
            ("x-autonomy-user".to_string(), "spoofed".to_string()),
        ],
        body_len: 0,
    };
    let (resp, body) = forward_with_body(&pool, &rhea, umbra_id, allowed, Vec::new()).await?;
    assert_eq!(resp.status, 200, "an opted-in app must serve a friend");
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(text.contains(&format!("peer={rhea_id}")), "peer id authoritative: {text}");
    assert!(text.contains(&format!("mesh={mesh_id}")), "mesh id injected: {text}");
    assert!(text.contains("device=rhea"), "device name verified: {text}");
    assert!(text.contains("rel=friend"), "relationship is friend: {text}");
    assert!(!text.contains("spoofed"), "spoofed headers stripped: {text}");
    Ok(())
}
