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

    let ifindex = adapter
        .get_adapter_index()
        .context("reading the adapter's interface index")?;

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
        ifindex,
    })
}

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2,
    GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, MIB_IPPROTO_NETMGMT};

fn route_row(ifindex: u32, net: ipnet::Ipv4Net) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = ifindex;
    row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
        u32::from_ne_bytes(net.network().octets());
    row.DestinationPrefix.PrefixLength = net.prefix_len();
    // On-link: an all-zero IPv4 next hop.
    row.NextHop.Ipv4.sin_family = AF_INET;
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

pub fn add_route(_name: &str, ifindex: u32, net: ipnet::Ipv4Net) -> Result<()> {
    let row = route_row(ifindex, net);
    match unsafe { CreateIpForwardEntry2(&row) } {
        NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        e => Err(std::io::Error::from_raw_os_error(e as i32)).context("CreateIpForwardEntry2"),
    }
}

pub fn del_route(_name: &str, ifindex: u32, net: ipnet::Ipv4Net) -> Result<()> {
    let row = route_row(ifindex, net);
    match unsafe { DeleteIpForwardEntry2(&row) } {
        NO_ERROR | ERROR_NOT_FOUND => Ok(()),
        e => Err(std::io::Error::from_raw_os_error(e as i32)).context("DeleteIpForwardEntry2"),
    }
}

/// The interface Windows itself would pick for the internet: the IPv4 default
/// route with the lowest route + interface metric, skipping `exclude`.
pub fn default_interface(exclude: u32) -> Option<u32> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET, &mut table) } != NO_ERROR || table.is_null() {
        return None;
    }
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let best = rows
        .iter()
        .filter(|r| {
            r.DestinationPrefix.PrefixLength == 0
                && r.InterfaceIndex != 0
                && r.InterfaceIndex != exclude
        })
        .filter_map(|r| {
            let iface = interface_metric(r.InterfaceIndex)?;
            Some((r.Metric.saturating_add(iface), r.InterfaceIndex))
        })
        .min()
        .map(|(_, index)| index);
    unsafe { FreeMibTable(table as *const _) };
    best
}

/// The interface's IPv4 metric, or None if it is down.
fn interface_metric(index: u32) -> Option<u32> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceIndex = index;
    if unsafe { GetIpInterfaceEntry(&mut row) } != NO_ERROR || row.Connected == 0 {
        return None;
    }
    Some(row.Metric)
}
