//! The subset of Tailscale's `tailcfg` JSON types this client uses.
//!
//! Go marshals struct fields under their Go names (PascalCase) and nil slices
//! as `null`, so most fields here are renamed and use [`null_default`].

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};

use crate::keys::{DiscoPublic, MachinePublic, NodePublic};

pub type NodeId = i64;

fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Hostinfo {
    #[serde(
        rename = "IPNVersion",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub ipn_version: String,
    #[serde(rename = "OS", skip_serializing_if = "String::is_empty", default)]
    pub os: String,
    #[serde(
        rename = "OSVersion",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub os_version: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hostname: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub go_arch: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RegisterResponseAuth {
    #[serde(rename = "AuthKey", skip_serializing_if = "String::is_empty")]
    pub auth_key: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterRequest {
    pub version: u16,
    pub node_key: NodePublic,
    pub old_node_key: NodePublic,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<RegisterResponseAuth>,
    /// Set to the AuthURL from a previous response to wait for interactive login.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub followup: String,
    pub hostinfo: Hostinfo,
    pub ephemeral: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Login {
    pub login_name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RegisterResponse {
    pub login: Login,
    pub node_key_expired: bool,
    pub machine_authorized: bool,
    #[serde(rename = "AuthURL")]
    pub auth_url: String,
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MapRequest {
    pub version: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub compress: String,
    pub keep_alive: bool,
    pub node_key: NodePublic,
    pub disco_key: DiscoPublic,
    pub stream: bool,
    pub hostinfo: Hostinfo,
    /// `ip:port` strings, as netip.AddrPort marshals.
    pub endpoints: Vec<String>,
    pub omit_peers: bool,
    pub read_only: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: NodeId,
    pub name: String,
    pub key: NodePublic,
    pub machine: MachinePublic,
    pub disco_key: DiscoPublic,
    #[serde(deserialize_with = "null_default")]
    pub addresses: Vec<IpNet>,
    #[serde(rename = "AllowedIPs", deserialize_with = "null_default")]
    pub allowed_ips: Vec<IpNet>,
    #[serde(deserialize_with = "null_default")]
    pub endpoints: Vec<String>,
    /// Legacy "127.3.3.40:<region>" form of the home DERP region.
    #[serde(rename = "DERP")]
    pub derp: String,
    #[serde(rename = "HomeDERP")]
    pub home_derp: i32,
    pub online: Option<bool>,
    pub machine_authorized: bool,
    pub expired: bool,
}

/// Incremental change to one peer (MapResponse.PeersChangedPatch).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PeerChange {
    #[serde(rename = "NodeID")]
    pub node_id: NodeId,
    #[serde(rename = "DERPRegion")]
    pub derp_region: i32,
    pub endpoints: Option<Vec<String>>,
    pub key: Option<NodePublic>,
    pub disco_key: Option<DiscoPublic>,
    pub online: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct MapResponse {
    pub keep_alive: bool,
    pub node: Option<Node>,
    /// When present, the full peer list (replaces what we had).
    pub peers: Option<Vec<Node>>,
    #[serde(deserialize_with = "null_default")]
    pub peers_changed: Vec<Node>,
    #[serde(deserialize_with = "null_default")]
    pub peers_removed: Vec<NodeId>,
    #[serde(deserialize_with = "null_default")]
    pub peers_changed_patch: Vec<PeerChange>,
    #[serde(rename = "DERPMap")]
    pub derp_map: Option<serde_json::Value>,
    pub domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_style_map_response() {
        let j = r#"{
            "Node": {"ID": 1, "Key": "nodekey:0000000000000000000000000000000000000000000000000000000000000001",
                     "Addresses": ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"], "AllowedIPs": null,
                     "Endpoints": null, "DERP": "127.3.3.40:1", "Online": true},
            "Peers": [], "PeersRemoved": null, "DERPMap": {"Regions": {}}
        }"#;
        let m: MapResponse = serde_json::from_str(j).unwrap();
        let n = m.node.unwrap();
        assert_eq!(n.id, 1);
        assert_eq!(n.addresses.len(), 2);
        assert!(n.allowed_ips.is_empty());
        assert_eq!(n.online, Some(true));
        assert!(m.peers.unwrap().is_empty());
    }
}
