# tsr: a small Tailscale client in Rust, for Windows

`tsr` joins a Tailscale network (tailnet), run either by tailscale.com or by
a self-hosted [Headscale](https://github.com/juanfont/headscale) server, and
brings up a WireGuard tunnel through a Wintun adapter. It speaks the real Tailscale
protocols, so it talks to stock Tailscale clients on your other machines.

It is a home project, not a replacement for the official client. Read
"Not done yet" before trusting it with anything.

## What works

Tested on 2026-10-20 against Headscale 0.26.1 and an unmodified `tailscaled`
1.84.3 peer:

- Registration with a pre-auth key or an interactive login URL.
- The control channel: `/key`, the `/ts2021` upgrade, the Noise IK handshake,
  HTTP/2 inside it, and the streaming map poll with incremental updates.
- Disco ping/pong to find a direct UDP path, in both directions, plus
  call-me-maybe through DERP to ask far-away peers to ping back.
- DERP relays: picks the nearest region, reports it to control, and relays
  traffic for peers it can't reach directly. Tested relay-only (`--derp-only`)
  with ping and HTTP both ways.
- WireGuard (via boringtun) to every peer, routed by AllowedIPs.
- ICMP and TCP both ways: OS `ping` from us to the peer, `tailscale ping`
  from the peer to us, and an HTTP request from the peer to a server behind
  our tunnel.
- On real Windows 11 it signs in to tailscale.com, creates the Wintun
  adapter and loads the netmap. Traffic to a peer on Windows hasn't been
  confirmed yet.

## Running it on Windows

1. Run Headscale somewhere on your LAN (a Raspberry Pi or NAS is fine), then
   create a user and a key:
   `headscale users create home` and
   `headscale preauthkeys create --user 1 --reusable --expiration 24h`.
2. Download `wintun.dll` (amd64) from <https://www.wintun.net> and put it next
   to `tsr.exe`.
3. In an **Administrator** terminal:

   ```
   tsr.exe up --login-server http://headscale.lan:8080 --auth-key <key>
   ```

   Keys are kept in `tsr.state.json` (use `--state` to move it), so later runs
   don't need `--auth-key`. Leave the key out to get a login URL instead.
4. From another terminal, `ping 100.64.0.x` for any peer.

Useful flags:

- `--no-tun --ping 100.64.0.4` exercises the whole path without creating an
  adapter, so no admin rights or wintun.dll are needed.
- `RUST_LOG=debug` turns on detailed logs.
- `TSR_CA_FILE=ca.pem` trusts an extra CA, for a Headscale server with a
  certificate from your own home CA.
- If UDP 41641 is taken (for example by the official Tailscale app), a random
  port is used instead. Quit the official app anyway: both claim 100.x routes.

On the very first run, the first packets to a peer can take up to 20 seconds
while the control server tells it about us. Later runs reuse the same keys
and connect at once. Round trips on a LAN are around 1 ms.

## Building

```
cargo build --release -p tsr                                  # native
cargo build --release -p tsr --target x86_64-pc-windows-gnu   # from Linux, needs mingw-w64
cargo test --workspace
```

On Windows with MSVC, a plain `cargo build --release` works.

## Layout

| Crate | What it does |
|---|---|
| `crates/tsr-control` | Keys (`mkey:`, `nodekey:`, `discokey:`), the Noise handshake and record layer (`noise.rs`), the `/ts2021` dial (`dial.rs`), the JSON wire types (`tailcfg.rs`), and register/map over HTTP/2 (`client.rs`). |
| `crates/tsr-net` | The WireGuard engine (`engine.rs`), disco (`disco.rs`), the DERP client (`derp.rs`), and the TUN device: Wintun on Windows, `/dev/net/tun` on Linux for development. |
| `crates/tsr` | The `tsr up` command: state file, login flow, netmap bookkeeping, reconnects. |

How a packet travels: the OS writes an IP packet to the adapter. The engine
picks the peer whose AllowedIPs match the destination, encrypts it with that
peer's boringtun session, and sends it over UDP to the path that disco
confirmed, or through the peer's home DERP region until there is one.
Incoming UDP and DERP traffic is either disco (magic `TS💬`) or WireGuard.
WireGuard packets are decrypted and written back to the adapter.

### Protocol notes worth knowing

- Tailscale's Noise record nonces use a **big-endian** counter, unlike standard
  Noise. That is why `noise.rs` is hand-written instead of using a crate.
- Headscale only stores a node's disco key and endpoints from a non-streaming
  `MapRequest` with `OmitPeers: true`. Without that request, peers never learn
  how to reach you. `start_map` sends it before opening the stream.
- A real Tailscale peer drops WireGuard packets from an `ip:port` until a disco
  ping from that address has tied it to our node key.
- When a peer sees our disco key change, it throws away its WireGuard session
  with us. That is why `tsr` keeps the disco key in its state file.

## Not done yet (roadmap)

Roughly in order of usefulness for a home network:

1. **Run on real Windows.** Check Wintun adapter creation, addressing via
   netsh, and the firewall prompt for UDP 41641.
2. **STUN.** We only advertise LAN addresses, so peers behind other NATs talk
   to us through DERP (slower) instead of punching a direct path.
3. **Packet filter.** We don't enforce the tailnet ACLs on inbound traffic;
   any peer can reach any port the Windows firewall allows.
4. **Run as a Windows service** that starts at boot, with the state file in
   `%ProgramData%` and readable only by SYSTEM. The keys are plaintext JSON
   today.
5. **MagicDNS**, so names like `nas.home.arpa` work.
6. IPv6 underlay sockets, zstd map compression, endpoint re-reporting when the
   LAN address changes, key expiry and re-login.
7. Subnet routes and exit nodes.
