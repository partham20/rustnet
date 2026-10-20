//! Keys that must survive restarts, stored as JSON.
//!
//! The machine key identifies this computer to the control server; the node
//! key is its WireGuard identity. Lose them and the server sees a new device.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tsr_control::keys::PrivateKey;

#[derive(Serialize, Deserialize)]
pub struct State {
    pub machine_key: PrivateKey,
    pub node_key: PrivateKey,
    /// Kept across restarts: when a peer sees our disco key change it drops
    /// its WireGuard session with us, which stalls traffic for ~15 seconds.
    #[serde(default = "PrivateKey::generate")]
    pub disco_key: PrivateKey,
}

impl State {
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let s = if path.exists() {
            let data =
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display()))?
        } else {
            tracing::info!("creating new state file {}", path.display());
            State {
                machine_key: PrivateKey::generate(),
                node_key: PrivateKey::generate(),
                disco_key: PrivateKey::generate(),
            }
        };
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        // Always rewrite, so files from older versions gain any new keys.
        std::fs::write(path, serde_json::to_vec_pretty(&s)?)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(s)
    }
}
