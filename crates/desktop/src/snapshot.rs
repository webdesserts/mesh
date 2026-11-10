//! Parsed view of `GET /status` + `GET /membership` for the tray and UI.

use crate::api_client::Client;
use anyhow::Result;
use serde_json::Value;

/// One active member row from `/membership`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow {
    pub peer_id: String,
    pub device_name: String,
    pub relationship: String,
}

/// Both daemon snapshots, fetched together.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub status: Value,
    pub membership: Value,
}

pub async fn fetch(client: &Client) -> Result<Snapshot> {
    let status = client.get_json("/status").await?;
    let membership = client.get_json("/membership").await?;
    Ok(Snapshot { status, membership })
}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or_default().to_string()
}

impl Snapshot {
    pub fn device_name(&self) -> String {
        text(&self.status, "device_name")
    }

    pub fn peer_id(&self) -> String {
        text(&self.status, "peer_id")
    }

    pub fn relay_listen(&self) -> bool {
        self.status.get("relay_listen").and_then(|v| v.as_bool()).unwrap_or(false)
    }

    pub fn notes_healthy(&self) -> bool {
        self.status.get("notes_sync_healthy").and_then(|v| v.as_bool()).unwrap_or(false)
    }

    pub fn entries_count(&self) -> u64 {
        self.membership.get("entries_count").and_then(|v| v.as_u64()).unwrap_or(0)
    }

    pub fn active_peers(&self) -> Vec<PeerRow> {
        self.membership
            .get("active_peers")
            .and_then(|v| v.as_array())
            .map(|rows| {
                rows.iter()
                    .map(|r| PeerRow {
                        peer_id: text(r, "peer_id"),
                        device_name: text(r, "device_name"),
                        relationship: text(r, "relationship"),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Header line: attached mode reports the external daemon explicitly.
    pub fn status_line(&self, mode: &str) -> String {
        if mode == "external daemon" {
            return "Mesh: Connected (external daemon)".to_string();
        }
        if self.entries_count() == 0 {
            format!("Mesh: {} · Unpaired", self.device_name())
        } else {
            format!(
                "Mesh: {} · {} active member(s)",
                self.device_name(),
                self.active_peers().len()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snap() -> Snapshot {
        Snapshot {
            status: json!({
                "device_name": "umbra",
                "peer_id": "0123456789abcdef",
                "mesh_id": "892fd3af",
                "relay_listen": true,
                "notes_sync_healthy": true
            }),
            membership: json!({
                "entries_count": 2,
                "active_peers": [
                    { "peer_id": "aaaa1111bbbb", "device_name": "rhea", "relationship": "self" }
                ]
            }),
        }
    }

    #[test]
    fn reads_status_fields() {
        let s = snap();
        assert_eq!(s.device_name(), "umbra");
        assert_eq!(s.peer_id(), "0123456789abcdef");
        assert!(s.relay_listen());
        assert!(s.notes_healthy());
        assert_eq!(s.entries_count(), 2);
        assert_eq!(s.active_peers().len(), 1);
        assert_eq!(s.active_peers()[0].relationship, "self");
    }

    #[test]
    fn status_line_paired_and_unpaired() {
        let s = snap();
        assert_eq!(s.status_line("in-process"), "Mesh: umbra · 1 active member(s)");
        assert_eq!(s.status_line("external daemon"), "Mesh: Connected (external daemon)");
        let mut unpaired = snap();
        unpaired.membership = json!({ "entries_count": 0, "active_peers": [] });
        assert_eq!(unpaired.status_line("in-process"), "Mesh: umbra · Unpaired");
    }

    #[test]
    fn missing_fields_default_empty() {
        let s = Snapshot { status: json!({}), membership: json!({}) };
        assert_eq!(s.device_name(), "");
        assert!(!s.relay_listen());
        assert_eq!(s.entries_count(), 0);
        assert!(s.active_peers().is_empty());
    }
}
