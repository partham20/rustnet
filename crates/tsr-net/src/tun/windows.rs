//! Wintun backend. Needs `wintun.dll` (from https://www.wintun.net) next to
//! the executable, and Administrator rights to create the adapter.

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::{TunChannels, TunConfig};

pub fn create(cfg: &TunConfig) -> Result<TunChannels> {
    let wintun = unsafe { wintun::load() }.context(
        "loading wintun.dll; download it from https://www.wintun.net and put it next to tsr.exe",
    )?;
    let adapter = match wintun::Adapter::open(&wintun, &cfg.name) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, &cfg.name, "Tailscale-rs", None)
            .context("creating Wintun adapter (are you running as Administrator?)")?,
    };

    let mask = u32::MAX
        .checked_shl(32 - u32::from(cfg.prefix_len))
        .unwrap_or(0);
    adapter
        .set_network_addresses_tuple(
            IpAddr::V4(cfg.address),
            IpAddr::V4(Ipv4Addr::from(mask)),
            None,
        )
        .context("setting adapter address")?;
    adapter
        .set_mtu(usize::from(cfg.mtu))
        .context("setting adapter MTU")?;

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);

    let reader = session.clone();
    std::thread::Builder::new()
        .name("wintun-rx".into())
        .spawn(move || loop {
            match reader.receive_blocking() {
                Ok(p) => {
                    if in_tx.blocking_send(p.bytes().to_vec()).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    tracing::warn!("wintun receive: {e}");
                    return;
                }
            }
        })?;

    let writer = session;
    std::thread::Builder::new()
        .name("wintun-tx".into())
        .spawn(move || {
            // Keep the adapter alive as long as the writer runs.
            let _adapter = adapter;
            while let Some(pkt) = out_rx.blocking_recv() {
                let Ok(len) = u16::try_from(pkt.len()) else {
                    continue;
                };
                match writer.allocate_send_packet(len) {
                    Ok(mut p) => {
                        p.bytes_mut().copy_from_slice(&pkt);
                        writer.send_packet(p);
                    }
                    Err(e) => tracing::debug!("wintun send: {e}"),
                }
            }
        })?;

    tracing::info!(name = %cfg.name, address = %cfg.address, "Wintun adapter up");
    Ok(TunChannels {
        from_os: in_rx,
        to_os: out_tx,
    })
}
