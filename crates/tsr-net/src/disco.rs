//! Tailscale "disco" messages: authenticated pings over the same UDP socket as
//! WireGuard, used to find a working direct path between two nodes.
//!
//! ```text
//! packet:  "TS💬" (6 bytes) | sender disco public key (32) | nonce (24) | NaCl box(payload)
//! payload: type (1) | version (1) | body
//! ping:    type 1, body = txid (12) | sender node key (32)
//! pong:    type 2, body = txid (12) | observed source: 16-byte IPv6(-mapped) addr | port u16 BE
//! ```
//!
//! A real Tailscale node only accepts WireGuard packets from an `ip:port` it
//! has associated with a node key, and it learns that association from a disco
//! ping. It only sends to us once one of its pings to us has been ponged.

use anyhow::{bail, ensure, Result};
use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use rand::RngCore;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

pub const MAGIC: &[u8; 6] = "TS💬".as_bytes().first_chunk::<6>().unwrap();
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + KEY_LEN + NONCE_LEN;

const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;
const TYPE_CALL_ME_MAYBE: u8 = 0x03;

pub type TxId = [u8; 12];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping { txid: TxId, node_key: [u8; 32] },
    Pong { txid: TxId, src: SocketAddr },
    CallMeMaybe { endpoints: Vec<SocketAddr> },
}

pub fn is_disco(packet: &[u8]) -> bool {
    packet.len() > HEADER_LEN && packet.starts_with(MAGIC)
}

/// The sender's disco public key, read without decrypting.
pub fn sender(packet: &[u8]) -> Option<[u8; 32]> {
    is_disco(packet).then(|| packet[6..38].try_into().unwrap())
}

pub fn new_txid() -> TxId {
    let mut t = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut t);
    t
}

fn encode_addr(a: SocketAddr) -> [u8; 18] {
    let ip6 = match a.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    let mut out = [0u8; 18];
    out[..16].copy_from_slice(&ip6.octets());
    out[16..].copy_from_slice(&a.port().to_be_bytes());
    out
}

fn decode_addr(b: &[u8]) -> SocketAddr {
    let ip6 = Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap());
    let ip = ip6
        .to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V6(ip6));
    SocketAddr::new(ip, u16::from_be_bytes([b[16], b[17]]))
}

impl Message {
    fn encode(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(64);
        match self {
            Message::Ping { txid, node_key } => {
                p.extend_from_slice(&[TYPE_PING, 0]);
                p.extend_from_slice(txid);
                p.extend_from_slice(node_key);
            }
            Message::Pong { txid, src } => {
                p.extend_from_slice(&[TYPE_PONG, 0]);
                p.extend_from_slice(txid);
                p.extend_from_slice(&encode_addr(*src));
            }
            Message::CallMeMaybe { endpoints } => {
                p.extend_from_slice(&[TYPE_CALL_ME_MAYBE, 0]);
                for e in endpoints {
                    p.extend_from_slice(&encode_addr(*e));
                }
            }
        }
        p
    }

    fn decode(p: &[u8]) -> Result<Self> {
        ensure!(p.len() >= 2, "short disco payload");
        let body = &p[2..];
        Ok(match p[0] {
            TYPE_PING => {
                ensure!(body.len() >= 12 + 32, "short ping");
                Message::Ping {
                    txid: body[..12].try_into()?,
                    node_key: body[12..44].try_into()?,
                }
            }
            TYPE_PONG => {
                ensure!(body.len() >= 12 + 18, "short pong");
                Message::Pong {
                    txid: body[..12].try_into()?,
                    src: decode_addr(&body[12..30]),
                }
            }
            TYPE_CALL_ME_MAYBE => Message::CallMeMaybe {
                endpoints: body.chunks_exact(18).map(decode_addr).collect(),
            },
            t => bail!("unknown disco message type {t}"),
        })
    }
}

/// Our disco identity; seals and opens messages to/from peers.
pub struct Disco {
    secret: SecretKey,
    public: [u8; 32],
}

impl Disco {
    pub fn new(private: [u8; 32]) -> Self {
        let secret = SecretKey::from(private);
        let public = *secret.public_key().as_bytes();
        Self { secret, public }
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    pub fn seal(&self, peer: &[u8; 32], msg: &Message) -> Vec<u8> {
        let b = SalsaBox::new(&PublicKey::from(*peer), &self.secret);
        let nonce = SalsaBox::generate_nonce(&mut crypto_box::aead::OsRng);
        let ct = b
            .encrypt(&nonce, msg.encode().as_slice())
            .expect("box seal cannot fail");
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    pub fn open(&self, packet: &[u8]) -> Result<([u8; 32], Message)> {
        let from = sender(packet).ok_or_else(|| anyhow::anyhow!("not a disco packet"))?;
        let b = SalsaBox::new(&PublicKey::from(from), &self.secret);
        let nonce = crypto_box::Nonce::from_slice(&packet[38..HEADER_LEN]);
        let pt = b
            .decrypt(nonce, &packet[HEADER_LEN..])
            .map_err(|_| anyhow::anyhow!("disco decryption failed"))?;
        Ok((from, Message::decode(&pt)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes() {
        assert_eq!(MAGIC, &[0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac]);
    }

    #[test]
    fn seal_open_round_trip() {
        let a = Disco::new([1; 32]);
        let b = Disco::new([2; 32]);
        let msgs = [
            Message::Ping {
                txid: new_txid(),
                node_key: [9; 32],
            },
            Message::Pong {
                txid: new_txid(),
                src: "192.168.1.20:41641".parse().unwrap(),
            },
            Message::Pong {
                txid: new_txid(),
                src: "[2001:db8::1]:5".parse().unwrap(),
            },
        ];
        for m in msgs {
            let p = a.seal(&b.public(), &m);
            assert!(is_disco(&p));
            let (from, got) = b.open(&p).unwrap();
            assert_eq!(from, a.public());
            assert_eq!(got, m);
        }
    }
}
