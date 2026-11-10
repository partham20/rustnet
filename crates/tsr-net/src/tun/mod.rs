//! The OS-facing virtual interface.
//!
//! Both backends expose the same shape: a blocking reader thread that feeds
//! packets into an mpsc channel, and a writer thread draining another one.

use anyhow::Result;
use ipnet::Ipv4Net;
use std::collections::BTreeSet;
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
    /// OS interface index of the adapter; 0 when there is none (`--no-tun`).
    pub ifindex: u32,
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
            ifindex: 0,
        },
        in_tx,
        out_rx,
    )
}

#[cfg(target_os = "linux")]
use linux as sys;
#[cfg(windows)]
use windows as sys;

/// Interface index holding the best default route, ignoring `exclude` (our
/// own adapter). This is where tsr's own traffic goes when an exit node owns
/// the internet routes.
pub fn default_interface(exclude: u32) -> Option<u32> {
    #[cfg(any(windows, target_os = "linux"))]
    return sys::default_interface(exclude);
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = exclude;
        None
    }
}

/// Extra IPv4 routes pointing into the adapter (subnet routes, exit node).
/// Only what changes is touched; everything is removed again on drop.
pub struct Routes {
    name: String,
    ifindex: u32,
    installed: BTreeSet<Ipv4Net>,
}

impl Routes {
    pub fn new(name: &str, ifindex: u32) -> Self {
        Self {
            name: name.to_string(),
            ifindex,
            installed: BTreeSet::new(),
        }
    }

    pub fn set(&mut self, want: &BTreeSet<Ipv4Net>) {
        let stale: Vec<_> = self.installed.difference(want).copied().collect();
        for net in stale {
            if let Err(e) = self.del(net) {
                tracing::warn!(%net, "removing route: {e:#}");
            }
            self.installed.remove(&net);
        }
        let missing: Vec<_> = want.difference(&self.installed).copied().collect();
        if !missing.is_empty() {
            tracing::info!(routes = ?missing, "adding routes into {}", self.name);
        }
        for net in missing {
            match self.add(net) {
                Ok(()) => {
                    self.installed.insert(net);
                }
                // Not recorded, so the next netmap tries again.
                Err(e) => tracing::warn!(%net, "adding route: {e:#}"),
            }
        }
    }

    #[allow(unused_variables)]
    fn add(&self, net: Ipv4Net) -> Result<()> {
        #[cfg(any(windows, target_os = "linux"))]
        return sys::add_route(&self.name, self.ifindex, net);
        #[cfg(not(any(windows, target_os = "linux")))]
        anyhow::bail!("routes are not supported on this OS");
    }

    #[allow(unused_variables)]
    fn del(&self, net: Ipv4Net) -> Result<()> {
        #[cfg(any(windows, target_os = "linux"))]
        return sys::del_route(&self.name, self.ifindex, net);
        #[cfg(not(any(windows, target_os = "linux")))]
        Ok(())
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        self.set(&BTreeSet::new());
    }
}
