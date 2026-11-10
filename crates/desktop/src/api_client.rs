//! Loopback HTTP client for the mesh daemon (`127.0.0.1:4620`).
//!
//! `Mesh.app` talks to the daemon over the same TCP API that external tools
//! use, so the tray and pairing window behave identically whether the daemon
//! runs in-process (owned) or was started by `webdesserts-mesh serve`
//! (attached). Mutating routes require `Authorization: Bearer <admin.token>`.

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

/// Build the base URL for a `listen_addr` such as `127.0.0.1:4620`.
pub fn base_url(listen_addr: &str) -> String {
    format!("http://{listen_addr}")
}

/// Shorten a `NodeId`/`PeerId` for display: first 12 chars plus an ellipsis.
pub fn short_id(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    if chars.len() <= 12 {
        id.to_string()
    } else {
        format!("{}…", chars[..12].iter().collect::<String>())
    }
}

/// Read the daemon admin bearer token (`0600`, written on first start).
pub fn read_admin_token(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read mesh admin token {}", path.display()))?;
    let token = raw.trim();
    if token.is_empty() {
        anyhow::bail!("mesh admin token {} is empty", path.display());
    }
    Ok(token.to_string())
}

/// Probe `GET /status` with a short timeout. `true` means an external daemon
/// already owns `listen_addr`, so `Mesh.app` should attach instead of starting
/// its own `MeshDaemon` (which would fail on the daemon lock and the port).
pub async fn probe(base: &str) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(400))
        .build()
        .unwrap_or_default();
    match client.get(format!("{base}/status")).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// Minimal JSON client bound to one daemon base URL and optional admin token.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl Client {
    pub fn new(base: String, token: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { http, base, token }
    }

    pub async fn get_json(&self, path: &str) -> Result<Value> {
        let resp = self
            .http
            .get(format!("{}{}", self.base, path))
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        json_or_error(resp, path).await
    }

    pub async fn post_json(&self, path: &str, body: Value) -> Result<Value> {
        let mut req = self.http.post(format!("{}{}", self.base, path)).json(&body);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.with_context(|| format!("POST {path}"))?;
        json_or_error(resp, path).await
    }
}

async fn json_or_error(resp: reqwest::Response, path: &str) -> Result<Value> {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("{path} failed with {status}: {}", text.trim());
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text).with_context(|| format!("parse {path} response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_wraps_listen_addr() {
        assert_eq!(base_url("127.0.0.1:4620"), "http://127.0.0.1:4620");
        assert_eq!(base_url("127.0.0.1:4621"), "http://127.0.0.1:4621");
    }

    #[test]
    fn short_id_truncates_only_when_long() {
        assert_eq!(short_id("abc"), "abc");
        assert_eq!(short_id("0123456789ab"), "0123456789ab");
        assert_eq!(short_id("0123456789abc"), "0123456789ab…");
    }

    #[test]
    fn read_admin_token_rejects_empty() {
        let dir = std::env::temp_dir().join(format!("mesh-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin.token");
        std::fs::write(&path, "  \n").unwrap();
        assert!(read_admin_token(&path).is_err());
        std::fs::write(&path, "secret\n").unwrap();
        assert_eq!(read_admin_token(&path).unwrap(), "secret");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
