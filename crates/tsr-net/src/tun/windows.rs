//! Wintun backend. Needs Administrator rights to create the adapter, and
//! `wintun.dll` (from https://www.wintun.net): either next to the executable,
//! or embedded at build time (see build.rs), in which case it is written next
//! to the executable on first use.

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::{TunChannels, TunConfig};

#[cfg(embed_wintun)]
const WINTUN_DLL: &[u8] = include_bytes!(env!("TSR_WINTUN_DLL_PATH"));

fn load_wintun() -> Result<wintun::Wintun> {
    if let Ok(w) = unsafe { wintun::load() } {
        return Ok(w);
    }
    #[cfg(embed_wintun)]
    {
        // Next to the exe, not in %TEMP%: that folder is exactly as trusted as
        // the exe itself, so an elevated tsr won't load a DLL that a less
        // trusted process could have planted.
        let path = std::env::current_exe()?.with_file_name("wintun.dll");
        if std::fs::read(&path).ok().as_deref() != Some(WINTUN_DLL) {
            std::fs::write(&path, WINTUN_DLL)
                .with_context(|| format!("writing {}", path.display()))?;
            tracing::info!("extracted {}", path.display());
        }
        return unsafe { wintun::load_from_path(&path) }.context("loading the bundled wintun.dll");
    }
    #[allow(unreachable_code)]
    {
        anyhow::bail!(
            "wintun.dll not found; download it from https://www.wintun.net and put it next to tsr.exe"
        )
    }
}

pub fn create(cfg: &TunConfig) -> Result<TunChannels> {
    let wintun = load_wintun()?;
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
