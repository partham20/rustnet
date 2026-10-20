//! Data plane of the client.
//!
//! * [`engine`]: one task that owns the UDP socket and every WireGuard peer.
//! * [`disco`]: Tailscale's disco ping/pong, used to agree on a direct path.
//! * [`tun`]: the OS network interface (Wintun on Windows, /dev/net/tun on Linux).
//! * [`packet`]: tiny IP helpers (destination lookup, ICMP echo for `--ping`).

pub mod disco;
pub mod engine;
pub mod packet;
pub mod tun;
