//! The WireGuard engine: one task that owns the UDP socket, every peer's
//! boringtun state machine, and the disco path-finding state.
//!
//! Packets from the OS arrive on an mpsc channel, are routed to a peer by
//! destination IP (longest AllowedIPs match), encrypted, and sent over UDP.
//! UDP datagrams are demultiplexed into disco or WireGuard, decrypted, and
//! handed back to the OS on another channel.

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

use crate::disco::{self, Disco, Message};
use crate::packet;

const MAX_PACKET: usize = 65535;
const TIMER_TICK: Duration = Duration::from_millis(250);
/// How often to disco-ping a peer's endpoints while we have no confirmed path.
const DISCO_PING_UNCONFIRMED: Duration = Duration::from_secs(3);
/// How often to re-ping a confirmed path to keep NAT mappings and the peer's
/// view of us fresh.
const DISCO_PING_CONFIRMED: Duration = Duration::from_secs(20);
/// A path with no traffic from the peer for this long is no longer trusted.
const PATH_TRUST: Duration = Duration::from_secs(60);

/// What the control plane tells us about one peer.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub name: String,
    pub node_key: [u8; 32],
    pub disco_key: [u8; 32],
    pub allowed_ips: Vec<IpNet>,
    pub endpoints: Vec<SocketAddr>,
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

struct Peer {
    cfg: PeerConfig,
    tunn: Tunn,
    /// Path confirmed by a disco pong or an authenticated WireGuard packet.
    path: Option<SocketAddr>,
    path_seen: Instant,
    last_ping: Option<Instant>,
    /// Pings we sent and are waiting on: txid -> destination.
    pings: HashMap<disco::TxId, SocketAddr>,
}

impl Peer {
    fn path(&self) -> Option<SocketAddr> {
        self.path.filter(|_| self.path_seen.elapsed() < PATH_TRUST)
    }

    fn candidates(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        // Our socket is IPv4-only for now.
        self.cfg.endpoints.iter().copied().filter(|e| e.is_ipv4())
    }
}

struct Engine {
    sock: Arc<UdpSocket>,
    static_private: StaticSecret,
    static_public: PublicKey,
    node_public: [u8; 32],
    disco: Disco,
    peers: HashMap<[u8; 32], Peer>,
    by_index: HashMap<u32, [u8; 32]>,
    by_disco: HashMap<[u8; 32], [u8; 32]>,
    next_index: u32,
    to_os: mpsc::Sender<Vec<u8>>,
}

/// Start the engine on its own task.
///
/// * `from_os`: IP packets the OS wants to send into the tailnet.
/// * `to_os`: decrypted IP packets for the OS.
pub async fn spawn(
    node_private: [u8; 32],
    disco_private: [u8; 32],
    listen_port: u16,
    mut from_os: mpsc::Receiver<Vec<u8>>,
    to_os: mpsc::Sender<Vec<u8>>,
) -> Result<EngineHandle> {
    let sock = Arc::new(
        UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), listen_port)).await?,
    );
    let local_addr = sock.local_addr()?;
    let static_private = StaticSecret::from(node_private);
    let static_public = PublicKey::from(&static_private);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(8);

    let mut e = Engine {
        sock: sock.clone(),
        node_public: static_public.to_bytes(),
        static_private,
        static_public,
        disco: Disco::new(disco_private),
        peers: HashMap::new(),
        by_index: HashMap::new(),
        by_disco: HashMap::new(),
        next_index: 1,
        to_os,
    };

    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET];
        let mut tick = tokio::time::interval(TIMER_TICK);
        loop {
            tokio::select! {
                r = sock.recv_from(&mut buf) => match r {
                    Ok((n, src)) => e.on_udp(&buf[..n], src).await,
                    // Windows reports ICMP port-unreachable as a recv error; ignore it.
                    Err(err) => tracing::trace!("udp recv: {err}"),
                },
                Some(pkt) = from_os.recv() => e.on_os_packet(&pkt).await,
                cmd = cmd_rx.recv() => match cmd {
                    Some(Command::SetPeers(p)) => e.set_peers(p).await,
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
    async fn set_peers(&mut self, configs: Vec<PeerConfig>) {
        let wanted: HashMap<[u8; 32], PeerConfig> =
            configs.into_iter().map(|c| (c.node_key, c)).collect();
        self.peers.retain(|k, _| wanted.contains_key(k));
        self.by_index.retain(|_, k| wanted.contains_key(k));
        self.by_disco.clear();

        for (key, cfg) in wanted {
            self.by_disco.insert(cfg.disco_key, key);
            if let Some(p) = self.peers.get_mut(&key) {
                p.cfg = cfg;
                continue;
            }
            let index = self.next_index;
            self.next_index += 1;
            let tunn = Tunn::new(
                self.static_private.clone(),
                PublicKey::from(key),
                None,
                Some(25),
                index,
                None,
            );
            tracing::info!(peer = %cfg.name, endpoints = ?cfg.endpoints, allowed = ?cfg.allowed_ips, "adding peer");
            self.by_index.insert(index, key);
            self.peers.insert(
                key,
                Peer {
                    cfg,
                    tunn,
                    path: None,
                    path_seen: Instant::now(),
                    last_ping: None,
                    pings: HashMap::new(),
                },
            );
        }
        // Start path discovery right away rather than on the next tick.
        let keys: Vec<_> = self.peers.keys().copied().collect();
        for k in keys {
            self.disco_ping(&k).await;
        }
    }

    fn route(&self, dst: IpAddr) -> Option<[u8; 32]> {
        self.peers
            .iter()
            .flat_map(|(k, p)| p.cfg.allowed_ips.iter().map(move |n| (k, n)))
            .filter(|(_, n)| n.contains(&dst))
            .max_by_key(|(_, n)| n.prefix_len())
            .map(|(k, _)| *k)
    }

    /// Send a WireGuard datagram to a peer: on its confirmed path if there is
    /// one, otherwise to every candidate endpoint.
    async fn send_wg(&self, key: &[u8; 32], data: &[u8]) {
        let Some(p) = self.peers.get(key) else { return };
        if let Some(path) = p.path() {
            let _ = self.sock.send_to(data, path).await;
            return;
        }
        for ep in p.candidates() {
            let _ = self.sock.send_to(data, ep).await;
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
        match peer.tunn.encapsulate(pkt, &mut out) {
            TunnResult::WriteToNetwork(d) => {
                let d = d.to_vec();
                self.send_wg(&key, &d).await;
            }
            TunnResult::Err(e) => tracing::debug!("encapsulate: {e:?}"),
            _ => {}
        }
    }

    async fn on_udp(&mut self, data: &[u8], src: SocketAddr) {
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

        let mut out = vec![0u8; MAX_PACKET];
        let mut datagram: &[u8] = data;
        loop {
            let peer = self.peers.get_mut(&key).unwrap();
            match peer.tunn.decapsulate(Some(src.ip()), datagram, &mut out) {
                TunnResult::WriteToNetwork(d) => {
                    // Authenticated: this source is a working path.
                    peer.path = Some(src);
                    peer.path_seen = Instant::now();
                    let _ = self.sock.send_to(d, src).await;
                    // Flush anything boringtun queued during the handshake.
                    datagram = &[];
                    continue;
                }
                TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                    peer.path = Some(src);
                    peer.path_seen = Instant::now();
                    let _ = self.to_os.send(p.to_vec()).await;
                }
                TunnResult::Done => {
                    if datagram.is_empty() {
                        break;
                    }
                    peer.path = Some(src);
                    peer.path_seen = Instant::now();
                }
                TunnResult::Err(e) => tracing::debug!(peer = %peer.cfg.name, "decapsulate: {e:?}"),
            }
            break;
        }
    }

    async fn on_disco(&mut self, data: &[u8], src: SocketAddr) {
        let Some(sender) = disco::sender(data) else {
            return;
        };
        let Some(key) = self.by_disco.get(&sender).copied() else {
            tracing::debug!(%src, "disco from unknown key");
            return;
        };
        let msg = match self.disco.open(data) {
            Ok((_, m)) => m,
            Err(e) => {
                tracing::debug!(%src, "disco: {e:#}");
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
                tracing::debug!(peer = %peer.cfg.name, %src, "disco ping");
                let pong = self
                    .disco
                    .seal(&peer.cfg.disco_key, &Message::Pong { txid, src });
                let _ = self.sock.send_to(&pong, src).await;
                if !peer.cfg.endpoints.contains(&src) {
                    peer.cfg.endpoints.push(src);
                }
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
                for e in endpoints {
                    if !peer.cfg.endpoints.contains(&e) {
                        peer.cfg.endpoints.push(e);
                    }
                }
                self.disco_ping(&key).await;
            }
        }
    }

    async fn disco_ping(&mut self, key: &[u8; 32]) {
        let node_public = self.node_public;
        let Some(peer) = self.peers.get_mut(key) else {
            return;
        };
        peer.last_ping = Some(Instant::now());
        peer.pings.clear();
        let targets: Vec<SocketAddr> = match peer.path() {
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
    }

    async fn on_tick(&mut self) {
        let keys: Vec<_> = self.peers.keys().copied().collect();
        let mut out = vec![0u8; MAX_PACKET];
        for key in keys {
            let peer = self.peers.get_mut(&key).unwrap();
            let interval = if peer.path().is_some() {
                DISCO_PING_CONFIRMED
            } else {
                DISCO_PING_UNCONFIRMED
            };
            let due = peer.last_ping.is_none_or(|t| t.elapsed() >= interval);
            match peer.tunn.update_timers(&mut out) {
                TunnResult::WriteToNetwork(d) => {
                    let d = d.to_vec();
                    self.send_wg(&key, &d).await;
                }
                TunnResult::Err(e) => tracing::trace!("timers: {e:?}"),
                _ => {}
            }
            if due {
                self.disco_ping(&key).await;
            }
        }
    }
}
