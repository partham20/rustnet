//! Control-plane half of a Tailscale client.
//!
//! * [`keys`]: machine / node / disco key types and their `prefix:hex` text form.
//! * [`noise`]: the `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake and record layer
//!   that Tailscale calls "controlbase".
//! * [`dial`]: the `/ts2021` HTTP upgrade that carries the Noise handshake.
//! * [`tailcfg`]: the subset of Tailscale's JSON wire types we need.
//! * [`client`]: HTTP/2 over the Noise channel; register and map-poll requests.

pub mod client;
pub mod dial;
pub mod keys;
pub mod noise;
pub mod tailcfg;

/// Capability version we advertise. Headscale and Tailscale's control server
/// change response shapes based on this number, so bump it deliberately.
pub const CAPABILITY_VERSION: u16 = 106;

/// Tailscale release we present as in Hostinfo.IPNVersion, which is what the
/// admin console shows and compares against the newest release to flag
/// "update available". It is display-only: control decides protocol details
/// from [`CAPABILITY_VERSION`], so this can track the latest stable release
/// without promising features we lack. Bump it when Tailscale ships.
pub const TAILSCALE_VERSION: &str = "1.104.1";
