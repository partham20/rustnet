//! Data plane of the client.
//!
//! * [`engine`]: one task that owns the UDP socket and every WireGuard peer.
//! * [`derp`]: Tailscale's DERP relay client, for peers we can't reach directly.
//! * [`disco`]: Tailscale's disco ping/pong, used to agree on a direct path.
//! * [`tun`]: the OS network interface (Wintun on Windows, /dev/net/tun on Linux).
//! * [`packet`]: tiny IP helpers (destination lookup, ICMP echo for `--ping`).

pub mod derp;
pub mod disco;
pub mod engine;
pub mod packet;
pub mod tun;

/// Local IPv4 addresses peers might reach us on, paired with our UDP port.
/// Skips loopback, link-local and Tailscale's own 100.64.0.0/10 range.
pub fn local_endpoints(port: u16) -> Vec<std::net::SocketAddr> {
    let cgnat: ipnet::Ipv4Net = "100.64.0.0/10".parse().unwrap();
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.ip() {
            std::net::IpAddr::V4(v4)
                if !v4.is_loopback() && !v4.is_link_local() && !cgnat.contains(&v4) =>
            {
                Some(v4)
            }
            _ => None,
        })
        .map(|ip| std::net::SocketAddr::new(ip.into(), port))
        .collect()
}
