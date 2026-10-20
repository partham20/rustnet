//! DERP ("Designated Encrypted Relay for Packets") client.
//!
//! When two nodes can't reach each other over UDP, they send WireGuard and
//! disco packets through a DERP server, addressed by node public key. The
//! server can't read them: they are already end-to-end encrypted.
//!
//! The connection is an HTTP(S) `GET /derp` upgraded to a framed protocol:
//!
//! ```text
//! frame:       type (1) | length u32 BE | payload
//! server key:  0x01  "DERP🔑" | server public key (32)
//! client info: 0x02  our public key (32) | nonce (24) | box(JSON)
//! server info: 0x03  nonce (24) | box(JSON)
//! send packet: 0x04  destination key (32) | packet
//! recv packet: 0x05  source key (32) | packet
//! keepalive:   0x06
//! preferred:   0x07  1 = this is our home region
//! ping / pong: 0x12 / 0x13  8 bytes echoed back
//! ```

use anyhow::{bail, ensure, Context, Result};
use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tsr_control::dial;
use tsr_control::tailcfg::DerpRegion;

const MAGIC: &[u8] = "DERP🔑".as_bytes();
const PROTOCOL_VERSION: u32 = 2;
const MAX_FRAME: usize = 64 << 10;

const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SERVER_INFO: u8 = 0x03;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_NOTE_PREFERRED: u8 = 0x07;
const FRAME_PING: u8 = 0x12;
const FRAME_PONG: u8 = 0x13;

/// A packet that arrived through DERP.
#[derive(Debug)]
pub struct Received {
    pub region: i32,
    pub src: [u8; 32],
    pub packet: Vec<u8>,
}

/// Handle to one region's connection; sending never blocks the engine.
#[derive(Clone)]
pub struct DerpClient {
    tx: mpsc::Sender<([u8; 32], Vec<u8>)>,
}

impl DerpClient {
    pub fn send(&self, dst: [u8; 32], packet: Vec<u8>) {
        // Dropping under pressure is fine: it's a lossy datagram path.
        let _ = self.tx.try_send((dst, packet));
    }
}

/// Start a connection to `region` that reconnects on its own.
pub fn spawn(
    region: DerpRegion,
    node_private: [u8; 32],
    preferred: bool,
    inbound: mpsc::Sender<Received>,
) -> DerpClient {
    let (tx, mut rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        loop {
            match run(&region, node_private, preferred, &inbound, &mut rx).await {
                Ok(()) => return, // engine dropped us
                Err(e) => tracing::warn!(region = %region.region_code, "DERP: {e:#}"),
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    });
    DerpClient { tx }
}

async fn read_frame(
    s: &mut (impl AsyncReadExt + Unpin),
    buf: &mut Vec<u8>,
) -> Result<(u8, Vec<u8>)> {
    // `buf` holds bytes read past the HTTP head that haven't been framed yet.
    while buf.len() < 5 {
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await?;
        ensure!(n > 0, "DERP connection closed");
        buf.extend_from_slice(&chunk[..n]);
    }
    let len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
    ensure!(len <= MAX_FRAME, "DERP frame too large ({len})");
    while buf.len() < 5 + len {
        let mut chunk = vec![0u8; (5 + len - buf.len()).max(4096)];
        let n = s.read(&mut chunk).await?;
        ensure!(n > 0, "DERP connection closed");
        buf.extend_from_slice(&chunk[..n]);
    }
    let frame: Vec<u8> = buf.drain(..5 + len).collect();
    Ok((frame[0], frame[5..].to_vec()))
}

fn frame(t: u8, payload: &[&[u8]]) -> Vec<u8> {
    let len: usize = payload.iter().map(|p| p.len()).sum();
    let mut f = Vec::with_capacity(5 + len);
    f.push(t);
    f.extend_from_slice(&(len as u32).to_be_bytes());
    for p in payload {
        f.extend_from_slice(p);
    }
    f
}

async fn run(
    region: &DerpRegion,
    node_private: [u8; 32],
    preferred: bool,
    inbound: &mpsc::Sender<Received>,
    outbound: &mut mpsc::Receiver<([u8; 32], Vec<u8>)>,
) -> Result<()> {
    let node = region
        .nodes
        .iter()
        .find(|n| !n.stun_only)
        .context("region has no DERP nodes")?;
    let url: url::Url = node.url().parse()?;
    let mut s = dial::connect(&url).await?;
    let req = format!(
        "GET /derp HTTP/1.1\r\nHost: {}\r\nUser-Agent: tsr\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
        node.host_name
    );
    s.write_all(req.as_bytes()).await?;
    let (status, _, mut buf) = dial::read_head(s.as_mut()).await?;
    ensure!(status == 101, "DERP upgrade failed: HTTP {status}");

    let (t, p) = read_frame(&mut s, &mut buf).await?;
    ensure!(
        t == FRAME_SERVER_KEY && p.len() >= MAGIC.len() + 32 && p.starts_with(MAGIC),
        "bad DERP server key frame"
    );
    let server_key: [u8; 32] = p[MAGIC.len()..MAGIC.len() + 32].try_into()?;

    let secret = SecretKey::from(node_private);
    let ours = *secret.public_key().as_bytes();
    let b = SalsaBox::new(&PublicKey::from(server_key), &secret);
    let nonce = SalsaBox::generate_nonce(&mut crypto_box::aead::OsRng);
    let info = format!(r#"{{"version":{PROTOCOL_VERSION},"CanAckPings":true}}"#);
    let sealed = b
        .encrypt(&nonce, info.as_bytes())
        .map_err(|_| anyhow::anyhow!("seal client info"))?;
    s.write_all(&frame(FRAME_CLIENT_INFO, &[&ours, &nonce, &sealed]))
        .await?;

    let (t, _) = read_frame(&mut s, &mut buf).await?;
    if t != FRAME_SERVER_INFO {
        bail!("expected DERP server info, got frame type {t:#x}");
    }
    if preferred {
        s.write_all(&frame(FRAME_NOTE_PREFERRED, &[&[1]])).await?;
    }
    tracing::info!(region = %region.region_code, node = %node.host_name, preferred, "DERP connected");

    let (mut r, mut w) = tokio::io::split(s);
    let (pong_tx, mut pong_rx) = mpsc::channel::<[u8; 8]>(8);
    let region_id = region.region_id;
    let reader = async {
        loop {
            let (t, p) = read_frame(&mut r, &mut buf).await?;
            match t {
                FRAME_RECV_PACKET if p.len() >= 32 => {
                    let src: [u8; 32] = p[..32].try_into().unwrap();
                    if inbound
                        .send(Received {
                            region: region_id,
                            src,
                            packet: p[32..].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        return Ok(());
                    }
                }
                FRAME_PING if p.len() >= 8 => {
                    let _ = pong_tx.try_send(p[..8].try_into().unwrap());
                }
                _ => {} // keepalive, peer gone, health, restarting...
            }
        }
    };
    let writer = async {
        loop {
            tokio::select! {
                pkt = outbound.recv() => match pkt {
                    Some((dst, data)) => w.write_all(&frame(FRAME_SEND_PACKET, &[&dst, &data])).await?,
                    None => return anyhow::Ok(()),
                },
                Some(data) = pong_rx.recv() => w.write_all(&frame(FRAME_PONG, &[&data])).await?,
            }
        }
    };
    tokio::select! {
        r = reader => r,
        w = writer => w,
    }
}
