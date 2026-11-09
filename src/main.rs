//! `mesh` CLI: `daemon`, `pair`, `status`.
//!
//! `pair` and `status` talk to the **running daemon** over its loopback HTTP
//! API. They must not call `MeshDaemon::start`, which would try to acquire
//! `mesh.lock` and fail immediately while the daemon holds it.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use webdesserts_mesh::MeshDaemon;
use webdesserts_mesh::config::{MeshConfig, MeshPaths};

#[derive(Parser)]
#[command(name = "webdesserts-mesh", about = "webdesserts mesh daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the mesh daemon (loopback API + proxy + poke gossip).
    Daemon {
        #[arg(long)]
        dir: Option<String>,
    },
    /// Pair with a peer using a one-time code (via the running daemon).
    Pair {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        code: String,
        #[arg(long)]
        peer_device_name: Option<String>,
        #[arg(long)]
        dir: Option<String>,
    },
    /// Print daemon status (via the running daemon).
    Status {
        #[arg(long)]
        dir: Option<String>,
    },
}

fn paths(dir: Option<String>) -> MeshPaths {
    match dir {
        Some(d) => MeshPaths::at(d),
        None => MeshPaths::default_paths(),
    }
}

/// Loopback base URL of the running daemon.
fn api_base(paths: &MeshPaths) -> String {
    let listen = paths
        .load_config()
        .map(|c| c.listen_addr)
        .unwrap_or_else(|_| webdesserts_mesh::config::DEFAULT_LISTEN_ADDR.to_string());
    format!("http://{listen}")
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Daemon { dir } => {
            let paths = paths(dir);
            paths.ensure_dir()?;
            let cfg = if paths.config.exists() {
                paths.load_config()?
            } else {
                let cfg = MeshConfig::new("mesh");
                paths.save_config(&cfg)?;
                cfg
            };
            let listen = cfg.listen_addr.clone();
            let daemon = Arc::new(MeshDaemon::start(paths, cfg).await?);
            daemon.start_poke_gossip().await?;
            let state = daemon.api_state();
            tracing::info!(listen = %listen, peer = %daemon.self_id, "mesh daemon up");
            webdesserts_mesh::api::serve(state, &listen).await?;
            Ok(())
        }
        Cmd::Pair {
            peer,
            code,
            peer_device_name,
            dir,
        } => {
            let paths = paths(dir);
            let base = api_base(&paths);
            let body = serde_json::json!({
                "peer": peer,
                "code": code,
                "peer_device_name": peer_device_name,
            });
            let resp = reqwest::Client::new()
                .post(format!("{base}/pair"))
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {base}/pair (is the daemon running?)"))?;
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if !status.is_success() {
                anyhow::bail!("pair failed ({status}): {text}");
            }
            println!("{text}");
            Ok(())
        }
        Cmd::Status { dir } => {
            let paths = paths(dir);
            let base = api_base(&paths);
            let resp = reqwest::Client::new()
                .get(format!("{base}/status"))
                .send()
                .await
                .with_context(|| format!("GET {base}/status (is the daemon running?)"))?;
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if !status.is_success() {
                anyhow::bail!("status failed ({status}): {text}");
            }
            println!("{text}");
            Ok(())
        }
    }
}
