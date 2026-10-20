//! The WireGuard engine: one task that owns the UDP socket, every peer's
//! boringtun state machine, the DERP connections, and disco path finding.
//!
//! Packets from the OS arrive on an mpsc channel, are routed to a peer by
//! destination IP (longest AllowedIPs match), encrypted, and sent either
//! directly over UDP (once disco has confirmed a path) or through the peer's
//! home DERP region. Incoming UDP and DERP traffic is demultiplexed into disco
//! or WireGuard, decrypted, and handed back to the OS on another channel.
//!
//! Like Tailscale, the engine is lazy: it only handshakes with and pings a
//! peer while there is traffic to or from it.

use anyhow::Result;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tsr_control::tailcfg::DerpMap;

use crate::derp::{self, DerpClient};
use crate::disco::{self, Disco, Message};
use crate::packet;

const MAX_PACKET: usize = 65535;
const TIMER_TICK: Duration = Duration::from_millis(250);
/// How often to disco-ping an active peer's endpoints while we have no direct path.
const DISCO_PING_UNCONFIRMED: Duration = Duration::from_secs(5);
/// How often to re-ping a confirmed path to keep NAT mappings fresh.
const DISCO_PING_CONFIRMED: Duration = Duration::from_secs(20);
/// A direct path with no traffic from the peer for this long is no longer trusted.
const PATH_TRUST: Duration = Duration::from_secs(60);
/// A peer with no traffic either way for this long is idle: no pings, no handshakes.
const ACTIVE_WINDOW: Duration = Duration::from_secs(120);
/// Disco pongs to pings that arrived over DERP report this magic address.
const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);

/// What the control plane tells us about one peer.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub name: String,
    pub node_key: [u8; 32],
    pub disco_key: [u8; 32],
    pub allowed_ips: Vec<IpNet>,
    pub endpoints: Vec<SocketAddr>,
    /// Home DERP region; 0 if unknown.
    pub derp_region: i32,
}

pub struct Options {
    pub node_private: [u8; 32],
    pub disco_private: [u8; 32],
    pub derp_map: DerpMap,
    /// Our home region; 0 for none.
    pub home_derp: i32,
    /// Never use direct UDP (for testing the relay path).
    pub derp_only: bool,
}

pub enum Command {
    SetPeers(Vec<PeerConfig>),
}

#[derive(Clone)]
pub struct EngineHandle {
    cmd: mpsc::Sender<Command>,
    pub local_addr: SocketAddr,
}

impl EngineHandle {
    pub async fn set_peers(&self, peers: Vec<PeerConfig>) -> Result<()> {
        self.cmd
            .send(Command::SetPeers(peers))
            .await
            .map_err(|_| anyhow::anyhow!("engine stopped"))
    }
}

/// Where a packet came from, and so where replies go.
#[derive(Debug, Clone, Copy)]
enum Src {
    Udp(SocketAddr),
    Derp { region: i32, key: [u8; 32] },
}

struct Peer {
    cfg: PeerConfig,
    tunn: Tunn,
    /// Direct path confirmed by a disco pong or an authenticated WireGuard packet.
    path: Option<SocketAddr>,
    path_seen: Instant,
    last_ping: Option<Instant>,
    last_active: Option<Instant>,
    /// Pings we sent and are waiting on: txid -> destination.
    pings: HashMap<disco::TxId, SocketAddr>,
}

impl Peer {
    fn path(&self) -> Option<SocketAddr> {
        self.path.filter(|_| self.path_seen.elapsed() < PATH_TRUST)
    }

    fn active(&self) -> bool {
        self.last_active
            .is_some_and(|t| t.elapsed() < ACTIVE_WINDOW)
    }

    fn candidates(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        // Our socket is IPv4-only for now.
        self.cfg.endpoints.iter().copied().filter(|e| e.is_ipv4())
    }
}

struct Engine {
    sock: Arc<UdpSocket>,
    opts: Options,
    static_private: StaticSecret,
    static_public: PublicKey,
    disco: Disco,
    peers: HashMap<[u8; 32], Peer>,
    by_index: HashMap<u32, [u8; 32]>,
    by_disco: HashMap<[u8; 32], [u8; 32]>,
    next_index: u32,
    derp: HashMap<i32, DerpClient>,
    derp_tx: mpsc::Sender<derp::Received>,
    to_os: mpsc::Sender<Vec<u8>>,
}

/// Bind the WireGuard/disco UDP socket, falling back to any free port when
/// `port` is taken (for example by the official Tailscale client).
pub async fn bind(port: u16) -> Result<UdpSocket> {
    let addr = |p| SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), p);
    match UdpSocket::bind(addr(port)).await {
        Ok(s) => Ok(s),
        Err(e) if port != 0 => {
            tracing::warn!("UDP port {port} unavailable ({e}); using a random port");
            Ok(UdpSocket::bind(addr(0)).await?)
        }
        Err(e) => Err(e.into()),
    }
}

/// Start the engine on its own task, using a socket from [`bind`].
///
/// * `from_os`: IP packets the OS wants to send into the tailnet.
/// * `to_os`: decrypted IP packets for the OS.
pub async fn spawn(
    opts: Options,
    sock: UdpSocket,
    mut from_os: mpsc::Receiver<Vec<u8>>,
    to_os: mpsc::Sender<Vec<u8>>,
) -> Result<EngineHandle> {
    let sock = Arc::new(sock);
    let local_addr = sock.local_addr()?;
    let static_private = StaticSecret::from(opts.node_private);
    let static_public = PublicKey::from(&static_private);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
    let (derp_tx, mut derp_rx) = mpsc::channel(1024);

    let mut e = Engine {
        sock: sock.clone(),
        static_private,
        static_public,
        disco: Disco::new(opts.disco_private),
        opts,
        peers: HashMap::new(),
        by_index: HashMap::new(),
        by_disco: HashMap::new(),
        next_index: 1,
        derp: HashMap::new(),
        derp_tx,
        to_os,
    };
    // Connect to our home region right away so peers can reach us.
    if e.opts.home_derp != 0 {
        e.derp_client(e.opts.home_derp);
    }

    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET];
        let mut tick = tokio::time::interval(TIMER_TICK);
        loop {
            tokio::select! {
                r = sock.recv_from(&mut buf) => match r {
                    Ok((n, src)) if !e.opts.derp_only => e.on_packet(&buf[..n], Src::Udp(src)).await,
                    Ok(_) => {}
                    // Windows reports ICMP port-unreachable as a recv error; ignore it.
                    Err(err) => tracing::trace!("udp recv: {err}"),
                },
                Some(d) = derp_rx.recv() => {
                    e.on_packet(&d.packet, Src::Derp { region: d.region, key: d.src }).await;
                }
                Some(pkt) = from_os.recv() => e.on_os_packet(&pkt).await,
                cmd = cmd_rx.recv() => match cmd {
                    Some(Command::SetPeers(p)) => e.set_peers(p),
                    None => break,
                },
                _ = tick.tick() => e.on_tick().await,
            }
        }
        tracing::info!("engine stopped");
    });

    Ok(EngineHandle {
        cmd: cmd_tx,
        local_addr,
    })
}

impl Engine {
    fn derp_client(&mut self, region: i32) -> Option<DerpClient> {
        if let Some(c) = self.derp.get(&region) {
            return Some(c.clone());
        }
        let r = self.opts.derp_map.regions.get(&region.to_string())?.clone();
        let c = derp::spawn(
            r,
            self.opts.node_private,
            region == self.opts.home_derp,
            self.derp_tx.clone(),
        );
        self.derp.insert(region, c.clone());
        Some(c)
    }

    fn set_peers(&mut self, configs: Vec<PeerConfig>) {
        let wanted: HashMap<[u8; 32], PeerConfig> =
            configs.into_iter().map(|c| (c.node_key, c)).collect();
        self.peers.retain(|k, _| wanted.contains_key(k));
        self.by_index.retain(|_, k| wanted.contains_key(k));
        self.by_disco.clear();

        for (key, cfg) in wanted {
            self.by_disco.insert(cfg.disco_key, key);
            if let Some(p) = self.peers.get_mut(&key) {
                // Keep endpoints we learned from disco on top of the netmap's.
                let learned: Vec<_> = p
                    .cfg
                    .endpoints
                    .iter()
                    .filter(|e| !cfg.endpoints.contains(e))
                    .copied()
                    .collect();
                p.cfg = cfg;
                p.cfg.endpoints.extend(learned);
                continue;
            }
            let index = self.next_index;
            self.next_index += 1;
            // No persistent keepalive: disco keeps paths warm, and idle peers stay quiet.
            let tunn = Tunn::new(
                self.static_private.clone(),
                PublicKey::from(key),
                None,
                None,
                index,
                None,
            );
            tracing::debug!(peer = %cfg.name, endpoints = ?cfg.endpoints, derp = cfg.derp_region, "adding peer");
            self.by_index.insert(index, key);
            self.peers.insert(
                key,
                Peer {
                    cfg,
                    tunn,
                    path: None,
                    path_seen: Instant::now(),
                    last_ping: None,
                    last_active: None,
                    pings: HashMap::new(),
                },
            );
        }
        tracing::info!(peers = self.peers.len(), "netmap applied");
    }

    fn route(&self, dst: IpAddr) -> Option<[u8; 32]> {
        self.peers
            .iter()
            .flat_map(|(k, p)| p.cfg.allowed_ips.iter().map(move |n| (k, n)))
            .filter(|(_, n)| n.contains(&dst))
            .max_by_key(|(_, n)| n.prefix_len())
            .map(|(k, _)| *k)
    }

    /// Send a WireGuard datagram to a peer: on its direct path if there is one,
    /// else through its home DERP region, else to every candidate endpoint.
    async fn send_wg(&mut self, key: &[u8; 32], data: &[u8]) {
        let Some(p) = self.peers.get(key) else { return };
        if !self.opts.derp_only {
            if let Some(path) = p.path() {
                let _ = self.sock.send_to(data, path).await;
                return;
            }
        }
        let region = p.cfg.derp_region;
        if region != 0 {
            if let Some(c) = self.derp_client(region) {
                c.send(*key, data.to_vec());
                return;
            }
        }
        if !self.opts.derp_only {
            let candidates: Vec<_> = self.peers[key].candidates().collect();
            for ep in candidates {
                let _ = self.sock.send_to(data, ep).await;
            }
        }
    }

    async fn reply(&mut self, src: Src, data: &[u8]) {
        match src {
            Src::Udp(addr) => {
                let _ = self.sock.send_to(data, addr).await;
            }
            Src::Derp { region, key } => {
                if let Some(c) = self.derp_client(region) {
                    c.send(key, data.to_vec());
                }
            }
        }
    }

    async fn on_os_packet(&mut self, pkt: &[u8]) {
        let Some(dst) = packet::dst_addr(pkt) else {
            return;
        };
        let Some(key) = self.route(dst) else {
            tracing::trace!(%dst, "no peer for destination");
            return;
        };
        let mut out = vec![0u8; pkt.len() + 148];
        let peer = self.peers.get_mut(&key).unwrap();
        let was_active = peer.active();
        peer.last_active = Some(Instant::now());
        let result = match peer.tunn.encapsulate(pkt, &mut out) {
            TunnResult::WriteToNetwork(d) => Some(d.to_vec()),
            TunnResult::Err(e) => {
                tracing::debug!("encapsulate: {e:?}");
                None
            }
            _ => None,
        };
        if !was_active {
            // Waking up an idle peer: start looking for a direct path now.
            self.disco_ping(&key).await;
        }
        if let Some(d) = result {
            self.send_wg(&key, &d).await;
        }
    }

    async fn on_packet(&mut self, data: &[u8], src: Src) {
        if disco::is_disco(data) {
            self.on_disco(data, src).await;
            return;
        }
        let key = match Tunn::parse_incoming_packet(data) {
            Ok(Packet::HandshakeInit(ref init)) => {
                match parse_handshake_anon(&self.static_private, &self.static_public, init) {
                    Ok(half) if self.peers.contains_key(&half.peer_static_public) => {
                        half.peer_static_public
                    }
                    _ => return,
                }
            }
            // Handshake response, cookie reply and data all carry our receiver
            // index; boringtun puts the peer index in the top 24 bits.
            Ok(_) => {
                let off = if data[0] == 2 { 8 } else { 4 };
                let idx = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) >> 8;
                match self.by_index.get(&idx) {
                    Some(k) => *k,
                    None => return,
                }
            }
            Err(_) => return,
        };
        if let Src::Derp { key: from, .. } = src {
            if from != key {
                return;
            }
        }

        let src_ip = match src {
            Src::Udp(a) => Some(a.ip()),
            Src::Derp { .. } => None,
        };
        let mut out = vec![0u8; MAX_PACKET];
        let mut datagram: &[u8] = data;
        loop {
            let peer = self.peers.get_mut(&key).unwrap();
            let res = peer.tunn.decapsulate(src_ip, datagram, &mut out);
            let ok = !matches!(res, TunnResult::Err(_));
            if ok {
                peer.last_active = Some(Instant::now());
                if let Src::Udp(addr) = src {
                    // Authenticated WireGuard from this address: it's a working path.
                    peer.path = Some(addr);
                    peer.path_seen = Instant::now();
                }
            }
            match res {
                TunnResult::WriteToNetwork(d) => {
                    let d = d.to_vec();
                    self.reply(src, &d).await;
                    // Flush anything boringtun queued during the handshake.
                    datagram = &[];
                    continue;
                }
                TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                    let _ = self.to_os.send(p.to_vec()).await;
                }
                TunnResult::Done => {}
                TunnResult::Err(e) => tracing::debug!(peer = %peer.cfg.name, "decapsulate: {e:?}"),
            }
            break;
        }
    }

    async fn on_disco(&mut self, data: &[u8], src: Src) {
        let Some(sender) = disco::sender(data) else {
            return;
        };
        let Some(key) = self.by_disco.get(&sender).copied() else {
            tracing::debug!(?src, "disco from unknown key");
            return;
        };
        let msg = match self.disco.open(data) {
            Ok((_, m)) => m,
            Err(e) => {
                tracing::debug!(?src, "disco: {e:#}");
                return;
            }
        };
        let peer = self.peers.get_mut(&key).unwrap();
        match msg {
            Message::Ping { txid, node_key } => {
                if node_key != key {
                    tracing::debug!(peer = %peer.cfg.name, "disco ping with mismatched node key");
                    return;
                }
                tracing::debug!(peer = %peer.cfg.name, ?src, "disco ping");
                let seen_as = match src {
                    Src::Udp(a) => {
                        if !peer.cfg.endpoints.contains(&a) {
                            peer.cfg.endpoints.push(a);
                        }
                        a
                    }
                    Src::Derp { region, .. } => {
                        SocketAddr::new(DERP_MAGIC_IP.into(), region as u16)
                    }
                };
                let pong = self
                    .disco
                    .seal(&peer.cfg.disco_key, &Message::Pong { txid, src: seen_as });
                self.reply(src, &pong).await;
            }
            Message::Pong { txid, src: seen_as } => {
                if let Some(dst) = peer.pings.remove(&txid) {
                    if peer.path() != Some(dst) {
                        tracing::info!(peer = %peer.cfg.name, path = %dst, %seen_as, "direct path confirmed");
                    }
                    peer.path = Some(dst);
                    peer.path_seen = Instant::now();
                }
            }
            Message::CallMeMaybe { endpoints } => {
                tracing::debug!(peer = %peer.cfg.name, ?endpoints, "call-me-maybe");
                for e in endpoints {
                    if !peer.cfg.endpoints.contains(&e) {
                        peer.cfg.endpoints.push(e);
                    }
                }
                peer.last_active = Some(Instant::now());
                self.disco_ping(&key).await;
            }
        }
    }

    /// Ping the peer's endpoints over UDP. Without a direct path, also ask it
    /// (through DERP) to ping us back, which opens NAT mappings both ways.
    async fn disco_ping(&mut self, key: &[u8; 32]) {
        if self.opts.derp_only {
            return;
        }
        let node_public = self.static_public.to_bytes();
        let Some(peer) = self.peers.get_mut(key) else {
            return;
        };
        peer.last_ping = Some(Instant::now());
        peer.pings.clear();
        let direct = peer.path();
        let targets: Vec<SocketAddr> = match direct {
            Some(p) => vec![p],
            None => peer.candidates().collect(),
        };
        for dst in targets {
            let txid = disco::new_txid();
            peer.pings.insert(txid, dst);
            let pkt = self.disco.seal(
                &peer.cfg.disco_key,
                &Message::Ping {
                    txid,
                    node_key: node_public,
                },
            );
            let _ = self.sock.send_to(&pkt, dst).await;
        }
        let region = peer.cfg.derp_region;
        if direct.is_none() && region != 0 {
            let local_port = self.sock.local_addr().map(|a| a.port()).unwrap_or(0);
            let endpoints = crate::local_endpoints(local_port);
            let cmm = self
                .disco
                .seal(&peer.cfg.disco_key, &Message::CallMeMaybe { endpoints });
            if let Some(c) = self.derp_client(region) {
                c.send(*key, cmm);
            }
        }
    }

    async fn on_tick(&mut self) {
        let keys: Vec<_> = self.peers.keys().copied().collect();
        let mut out = vec![0u8; MAX_PACKET];
        for key in keys {
            let peer = self.peers.get_mut(&key).unwrap();
            if !peer.active() {
                continue;
            }
            let interval = if peer.path().is_some() {
                DISCO_PING_CONFIRMED
            } else {
                DISCO_PING_UNCONFIRMED
            };
            let due = peer.last_ping.is_none_or(|t| t.elapsed() >= interval);
            let timer_out = match peer.tunn.update_timers(&mut out) {
                TunnResult::WriteToNetwork(d) => Some(d.to_vec()),
                TunnResult::Err(e) => {
                    tracing::trace!("timers: {e:?}");
                    None
                }
                _ => None,
            };
            if let Some(d) = timer_out {
                self.send_wg(&key, &d).await;
            }
            if due {
                self.disco_ping(&key).await;
            }
        }
    }
}
