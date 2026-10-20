//! The OS-facing virtual interface.
//!
//! Both backends expose the same shape: a blocking reader thread that feeds
//! packets into an mpsc channel, and a writer thread draining another one.

use anyhow::Result;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

pub struct TunConfig {
    pub name: String,
    pub address: Ipv4Addr,
    /// Prefix length used for the on-link route; 10 covers Tailscale's 100.64.0.0/10.
    pub prefix_len: u8,
    pub mtu: u16,
}

/// Packets read from the OS, and a sender for packets to write to it.
pub struct TunChannels {
    pub from_os: mpsc::Receiver<Vec<u8>>,
    pub to_os: mpsc::Sender<Vec<u8>>,
}

pub fn create(cfg: &TunConfig) -> Result<TunChannels> {
    #[cfg(windows)]
    return windows::create(cfg);
    #[cfg(target_os = "linux")]
    return linux::create(cfg);
    #[cfg(not(any(windows, target_os = "linux")))]
    anyhow::bail!("no TUN backend for this OS yet ({:?})", cfg.name);
}

/// Channels with no OS behind them, for `--no-tun` testing.
pub fn detached() -> (TunChannels, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
    let (in_tx, in_rx) = mpsc::channel(256);
    let (out_tx, out_rx) = mpsc::channel(256);
    (
        TunChannels {
            from_os: in_rx,
            to_os: out_tx,
        },
        in_tx,
        out_rx,
    )
}
