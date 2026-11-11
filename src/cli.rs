//! Shared `webdesserts-mesh` CLI: `daemon`, `pair`, `status`.
//!
//! Used by the standalone `webdesserts-mesh` binary and by `Mesh.app` when it
//! is invoked through the Homebrew Cask `binary` symlink
//! (`/opt/homebrew/bin/webdesserts-mesh -> Mesh.app/Contents/MacOS/Mesh`).
//!
//! `pair` and `status` talk to the **running daemon** over its loopback HTTP
//! API. They must not call `MeshDaemon::start`, which would try to acquire
//! `mesh.lock` and fail immediately while the daemon holds it.

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::MeshDaemon;
use crate::config::{MeshConfig, MeshPaths};

/// `argv[0]` file stem that routes an invocation to the CLI.
pub const CLI_STEM: &str = "webdesserts-mesh";

#[derive(Parser)]
#[command(name = "webdesserts-mesh", version, about = "webdesserts mesh daemon")]
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

/// `true` solely when `argv[0]`'s file stem is `webdesserts-mesh`.
///
/// `args[1..]` is deliberately ignored so `open --args`, deep links,
/// LaunchServices `-psn_*` and updater relaunch arguments never reach `clap`.
pub fn should_dispatch_cli(args: &[OsString]) -> bool {
    args.first()
        .and_then(|a0| Path::new(a0).file_stem())
        .is_some_and(|stem| stem == CLI_STEM)
}

/// Parse `args` (including `argv[0]`) and run the selected command.
pub fn run_from_os_args(args: Vec<OsString>) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .try_init();
    let cli = Cli::parse_from(args);
    tokio::runtime::Runtime::new()
        .context("start tokio runtime")?
        .block_on(run(cli))
}

fn paths(dir: Option<String>) -> Result<MeshPaths> {
    match dir {
        Some(d) => Ok(MeshPaths::at(d)),
        None => MeshPaths::resolve(),
    }
}

/// Loopback base URL of the running daemon.
fn api_base(paths: &MeshPaths) -> String {
    let listen = paths
        .load_config()
        .map(|c| c.listen_addr)
        .unwrap_or_else(|_| crate::config::DEFAULT_LISTEN_ADDR.to_string());
    format!("http://{listen}")
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Daemon { dir } => {
            let paths = paths(dir)?;
            paths.ensure_dir()?;
            let cfg = if paths.config.exists() {
                paths.load_config()?
            } else {
                let cfg = MeshConfig::new("mesh");
                paths.save_config(&cfg)?;
                cfg
            };
            let listen = cfg.listen_addr.clone();
            let register_sock = paths.register_sock.clone();
            let daemon = Arc::new(MeshDaemon::start(paths, cfg).await?);
            daemon.start_poke_gossip().await?;
            let state = daemon.api_state();
            tracing::info!(listen = %listen, peer = %daemon.self_id, "mesh daemon up");
            // Local app registration socket (0600, pre-authenticated by OS perms).
            let uds_state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::api::serve_uds(uds_state, register_sock).await {
                    tracing::warn!(error = %e, "register.sock server failed");
                }
            });
            crate::api::serve(state, &listen).await?;
            Ok(())
        }
        Cmd::Pair {
            peer,
            code,
            peer_device_name,
            dir,
        } => {
            let paths = paths(dir)?;
            let base = api_base(&paths);
            let body = serde_json::json!({
                "peer": peer,
                "code": code,
                "peer_device_name": peer_device_name,
            });
            let token = std::fs::read_to_string(&paths.admin_token)
                .with_context(|| format!("read {}", paths.admin_token.display()))?;
            let resp = reqwest::Client::new()
                .post(format!("{base}/pair"))
                .bearer_auth(token.trim())
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
            let paths = paths(dir)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn dispatches_on_cask_symlink_stem() {
        assert!(should_dispatch_cli(&os(&["/opt/homebrew/bin/webdesserts-mesh", "status"])));
        assert!(should_dispatch_cli(&os(&["webdesserts-mesh"])));
        assert!(should_dispatch_cli(&os(&["./target/debug/webdesserts-mesh", "daemon"])));
    }

    #[test]
    fn never_dispatches_bundle_exe_regardless_of_args() {
        let exe = "/Applications/Mesh.app/Contents/MacOS/Mesh";
        assert!(!should_dispatch_cli(&os(&[exe])));
        assert!(!should_dispatch_cli(&os(&[exe, "status"])));
        assert!(!should_dispatch_cli(&os(&[exe, "-psn_0_12345"])));
        assert!(!should_dispatch_cli(&os(&[exe, "webdesserts-mesh"])));
        assert!(!should_dispatch_cli(&os(&["/opt/homebrew/bin/webdesserts-mesh-old"])));
        assert!(!should_dispatch_cli(&[]));
    }

    #[test]
    fn cli_definition_is_valid_and_parses() {
        Cli::command().debug_assert();
        let cli = Cli::try_parse_from(["webdesserts-mesh", "status", "--dir", "/x"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Status { dir: Some(ref d) } if d == "/x"));
    }
}
