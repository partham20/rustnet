//! `tsr`: a minimal Tailscale client.
//!
//! ```text
//! tsr up --login-server http://headscale.lan:8080 --auth-key <key>
//! ```

mod state;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use tsr_control::client::ControlClient;
use tsr_control::tailcfg::{
    Hostinfo, MapRequest, MapResponse, Node, NodeId, RegisterRequest, RegisterResponseAuth,
};
use tsr_control::CAPABILITY_VERSION;
use tsr_net::engine::PeerConfig;
use tsr_net::{packet, tun};
use url::Url;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Log in (if needed), bring the tunnel up, and stay connected.
    Up(UpArgs),
}

#[derive(clap::Args)]
struct UpArgs {
    /// Control server URL, e.g. http://headscale.lan:8080
    #[arg(long)]
    login_server: Url,
    /// Pre-auth key. Without one, a login URL is printed to open in a browser.
    #[arg(long, env = "TSR_AUTH_KEY")]
    auth_key: Option<String>,
    /// Where machine and node keys are kept.
    #[arg(long, default_value = "tsr.state.json")]
    state: PathBuf,
    /// Name shown in the tailnet. Defaults to this computer's name.
    #[arg(long)]
    hostname: Option<String>,
    /// UDP port for WireGuard and disco.
    #[arg(long, default_value_t = 41641)]
    port: u16,
    /// Name of the virtual network adapter.
    #[arg(long, default_value = "tsr0")]
    tun_name: String,
    /// Don't create a network adapter (useful with --ping, or without admin rights).
    #[arg(long)]
    no_tun: bool,
    /// Send ICMP echo requests through the tunnel to this tailnet IP and print replies.
    #[arg(long)]
    ping: Option<Ipv4Addr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,h2=warn".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Up(a) => up(a).await,
    }
}

fn default_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "tsr".into())
        .to_lowercase()
}

/// Local IPv4 addresses peers might reach us on, paired with our UDP port.
fn local_endpoints(port: u16) -> Vec<String> {
    let cgnat: ipnet::Ipv4Net = "100.64.0.0/10".parse().unwrap();
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.ip() {
            IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_link_local() && !cgnat.contains(&v4) => {
                Some(v4)
            }
            _ => None,
        })
        .map(|ip| SocketAddr::new(ip.into(), port).to_string())
        .collect()
}

async fn up(a: UpArgs) -> Result<()> {
    let st = state::State::load_or_create(&a.state)?;
    // A fresh disco key each run is what Tailscale does too.
    let disco_key = tsr_control::keys::PrivateKey::generate();
    let hostinfo = Hostinfo {
        hostname: a.hostname.clone().unwrap_or_else(default_hostname),
        os: std::env::consts::OS.into(),
        go_arch: std::env::consts::ARCH.into(),
        ipn_version: concat!("1.84.0-tsr", env!("CARGO_PKG_VERSION")).into(),
        ..Default::default()
    };

    let mut client = ControlClient::connect(&a.login_server, &st.machine_key).await?;
    register(&mut client, &st, &hostinfo, a.auth_key.clone()).await?;

    let endpoints = local_endpoints(a.port);
    tracing::info!(?endpoints, "advertising endpoints");
    let map_req = MapRequest {
        version: CAPABILITY_VERSION,
        node_key: st.node_key.node_public(),
        disco_key: disco_key.disco_public(),
        stream: true,
        keep_alive: true,
        hostinfo: hostinfo.clone(),
        endpoints,
        ..Default::default()
    };
    let mut stream = start_map(&mut client, &map_req).await?;
    let first = stream
        .next()
        .await?
        .context("control closed the map stream before the first netmap")?;
    let me = first
        .node
        .clone()
        .context("first netmap has no self node")?;
    let my_v4 = me
        .addresses
        .iter()
        .find_map(|n| match n.addr() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .context("no IPv4 tailnet address assigned")?;
    println!("Connected as {} with address {my_v4}", me.name);

    // With --no-tun, packets go to and from in-process channels instead of the OS.
    let (channels, test_io) = if a.no_tun {
        let (c, inject, received) = tun::detached();
        (c, Some((inject, received)))
    } else {
        let c = tun::create(&tun::TunConfig {
            name: a.tun_name.clone(),
            address: my_v4,
            prefix_len: 10,
            mtu: 1280,
        })?;
        (c, None)
    };

    let engine = tsr_net::engine::spawn(
        st.node_key.0,
        disco_key.0,
        a.port,
        channels.from_os,
        channels.to_os,
    )
    .await?;
    tracing::info!(local = %engine.local_addr, "WireGuard engine listening");

    if let Some(target) = a.ping {
        match test_io {
            Some((inject, received)) => {
                tokio::spawn(pinger(my_v4, target, inject, received));
            }
            None => println!("Tunnel is up: try `ping {target}` from another terminal."),
        }
    }

    let mut netmap = Netmap::default();
    netmap.apply(first);
    engine.set_peers(netmap.peer_configs()).await?;

    loop {
        match stream.next().await {
            Ok(Some(m)) => {
                if m.keep_alive
                    && m.node.is_none()
                    && m.peers.is_none()
                    && m.peers_changed.is_empty()
                {
                    continue;
                }
                netmap.apply(m);
                engine.set_peers(netmap.peer_configs()).await?;
                continue;
            }
            Ok(None) => tracing::warn!("map stream ended"),
            Err(e) => tracing::warn!("map stream: {e:#}"),
        }
        // Reconnect, keeping the engine and its sessions.
        stream = loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            match reconnect(&a, &st, &map_req).await {
                Ok(s) => break s,
                Err(e) => tracing::warn!("reconnect: {e:#}"),
            }
        };
    }
}

async fn reconnect(
    a: &UpArgs,
    st: &state::State,
    req: &MapRequest,
) -> Result<tsr_control::client::MapStream> {
    let mut c = ControlClient::connect(&a.login_server, &st.machine_key).await?;
    let mut req = req.clone();
    req.endpoints = local_endpoints(a.port);
    start_map(&mut c, &req).await
}

/// Report our endpoints, disco key and hostinfo, then open the streaming poll.
///
/// Like Tailscale's own client, this sends a non-streaming "endpoint update"
/// first; Headscale only records disco key and endpoints from that kind of
/// request, and peers can't reach us without them.
async fn start_map(
    c: &mut ControlClient,
    req: &MapRequest,
) -> Result<tsr_control::client::MapStream> {
    let update = MapRequest {
        stream: false,
        omit_peers: true,
        keep_alive: false,
        ..req.clone()
    };
    let mut s = c.map(&update).await.context("endpoint update")?;
    while s.next().await?.is_some() {}
    c.map(req).await
}

async fn register(
    client: &mut ControlClient,
    st: &state::State,
    hostinfo: &Hostinfo,
    auth_key: Option<String>,
) -> Result<()> {
    let mut req = RegisterRequest {
        version: CAPABILITY_VERSION,
        node_key: st.node_key.node_public(),
        auth: auth_key.map(|k| RegisterResponseAuth { auth_key: k }),
        hostinfo: hostinfo.clone(),
        ..Default::default()
    };
    let resp = client.register(&req).await?;
    if !resp.error.is_empty() {
        bail!("registration failed: {}", resp.error);
    }
    if resp.machine_authorized {
        tracing::info!(user = %resp.login.login_name, "registered");
        return Ok(());
    }
    if resp.auth_url.is_empty() {
        bail!("server neither authorized this machine nor gave a login URL");
    }
    println!("\nTo authenticate, visit:\n\n\t{}\n", resp.auth_url);
    // The follow-up request blocks until the login completes.
    req.followup = resp.auth_url;
    req.auth = None;
    let resp = client.register(&req).await?;
    if !resp.error.is_empty() || !resp.machine_authorized {
        bail!("login did not complete: {}", resp.error);
    }
    tracing::info!(user = %resp.login.login_name, "registered");
    Ok(())
}

/// Our view of the tailnet, updated from full and incremental map responses.
#[derive(Default)]
struct Netmap {
    peers: BTreeMap<NodeId, Node>,
}

impl Netmap {
    fn apply(&mut self, m: MapResponse) {
        if let Some(peers) = m.peers {
            self.peers = peers.into_iter().map(|p| (p.id, p)).collect();
        }
        for p in m.peers_changed {
            self.peers.insert(p.id, p);
        }
        for id in m.peers_removed {
            self.peers.remove(&id);
        }
        for patch in m.peers_changed_patch {
            if let Some(p) = self.peers.get_mut(&patch.node_id) {
                if let Some(e) = patch.endpoints {
                    p.endpoints = e;
                }
                if let Some(k) = patch.key {
                    p.key = k;
                }
                if let Some(k) = patch.disco_key {
                    p.disco_key = k;
                }
                if patch.online.is_some() {
                    p.online = patch.online;
                }
            }
        }
    }

    fn peer_configs(&self) -> Vec<PeerConfig> {
        self.peers
            .values()
            .filter(|p| !p.expired)
            .map(|p| PeerConfig {
                name: p.name.clone(),
                node_key: p.key.0,
                disco_key: p.disco_key.0,
                allowed_ips: if p.allowed_ips.is_empty() {
                    p.addresses.clone()
                } else {
                    p.allowed_ips.clone()
                },
                endpoints: p.endpoints.iter().filter_map(|e| e.parse().ok()).collect(),
            })
            .collect()
    }
}

async fn pinger(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    inject: mpsc::Sender<Vec<u8>>,
    mut received: mpsc::Receiver<Vec<u8>>,
) {
    let id = std::process::id() as u16;
    let mut sent = BTreeMap::new();
    let mut seq: u16 = 0;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                seq = seq.wrapping_add(1);
                sent.insert(seq, std::time::Instant::now());
                let _ = inject.send(packet::icmp_echo_request(src, dst, id, seq)).await;
            }
            Some(pkt) = received.recv() => {
                if let Some((from, rid, rseq)) = packet::parse_icmp_echo_reply(&pkt) {
                    if rid == id {
                        let rtt = sent.remove(&rseq).map(|t| t.elapsed());
                        println!("reply from {from}: seq={rseq} time={rtt:?}");
                    }
                }
            }
        }
    }
}
