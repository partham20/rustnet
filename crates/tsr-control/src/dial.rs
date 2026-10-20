//! Connecting to a control server: plain HTTP for `/key`, then an HTTP/1.1
//! upgrade on `/ts2021` that carries the Noise handshake. After the upgrade
//! the socket speaks Noise records, and inside those, HTTP/2.

use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use url::Url;

use crate::keys::{MachinePublic, PrivateKey};
use crate::noise::{self, ClientHandshake, Transport};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Bytes the server sends first on the Noise channel, ahead of HTTP/2.
const EARLY_PAYLOAD_MAGIC: &[u8; 5] = b"\xff\xff\xffTS";

#[derive(Debug, Default, Clone, Deserialize)]
pub struct EarlyNoise {
    #[serde(rename = "nodeKeyChallenge", default)]
    pub node_key_challenge: String,
}

/// TCP (and TLS for https URLs) connection to the control server.
pub async fn connect(server: &Url) -> Result<Box<dyn Stream>> {
    let host = server
        .host_str()
        .context("server URL has no host")?
        .to_string();
    let port = server
        .port_or_known_default()
        .context("server URL has no port")?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("connecting to {host}:{port}"))?;
    tcp.set_nodelay(true)?;
    match server.scheme() {
        "http" => Ok(Box::new(tcp)),
        "https" => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(host.clone())?;
            let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, tcp)
                .await?;
            Ok(Box::new(tls))
        }
        s => bail!("unsupported URL scheme {s:?}"),
    }
}

fn host_header(server: &Url) -> String {
    let host = server.host_str().unwrap_or_default();
    match server.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    }
}

/// Read an HTTP/1.1 response head. Returns (status, headers, leftover body bytes).
async fn read_head(s: &mut dyn Stream) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        ensure!(buf.len() < 64 * 1024, "HTTP response head too large");
        let n = s.read(&mut chunk).await?;
        ensure!(n > 0, "connection closed while reading HTTP response");
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..end]).context("non-UTF-8 HTTP head")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("bad status line {status_line:?}"))?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Ok((status, headers, buf[end + 4..].to_vec()))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Read the whole body of a `Connection: close` response, de-chunking if needed.
async fn read_body(
    s: &mut dyn Stream,
    headers: &[(String, String)],
    mut body: Vec<u8>,
) -> Result<Vec<u8>> {
    s.read_to_end(&mut body).await?;
    if header(headers, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        let mut out = Vec::new();
        let mut rest = &body[..];
        loop {
            let nl = rest
                .windows(2)
                .position(|w| w == b"\r\n")
                .context("bad chunk")?;
            let size_str = std::str::from_utf8(&rest[..nl])?
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            let size = usize::from_str_radix(size_str, 16)?;
            rest = &rest[nl + 2..];
            if size == 0 {
                break;
            }
            ensure!(rest.len() >= size + 2, "truncated chunk");
            out.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
        body = out;
    }
    Ok(body)
}

/// `GET /key?v=N`: the control server's Noise public key.
pub async fn fetch_server_key(server: &Url, capver: u16) -> Result<MachinePublic> {
    #[derive(Deserialize)]
    struct KeyResponse {
        #[serde(rename = "publicKey")]
        public_key: MachinePublic,
    }
    let mut s = connect(server).await?;
    let req = format!(
        "GET /key?v={capver} HTTP/1.1\r\nHost: {}\r\nUser-Agent: tsr\r\nConnection: close\r\n\r\n",
        host_header(server)
    );
    s.write_all(req.as_bytes()).await?;
    let (status, headers, rest) = read_head(s.as_mut()).await?;
    let body = read_body(s.as_mut(), &headers, rest).await?;
    ensure!(
        status == 200,
        "GET /key: HTTP {status}: {}",
        String::from_utf8_lossy(&body)
    );
    let k: KeyResponse = serde_json::from_slice(&body).context("parsing /key response")?;
    Ok(k.public_key)
}

/// A finished ts2021 connection: a plaintext byte stream for HTTP/2, plus the
/// server's early payload once it arrives.
pub struct NoiseConn {
    pub stream: DuplexStream,
    pub early: oneshot::Receiver<EarlyNoise>,
}

/// Do the `/ts2021` upgrade and Noise handshake, then start pumping records.
pub async fn dial_ts2021(
    server: &Url,
    machine_key: &PrivateKey,
    control_key: &MachinePublic,
    capver: u16,
) -> Result<NoiseConn> {
    let (hs, init) = ClientHandshake::start(machine_key, control_key, capver)?;
    let mut s = connect(server).await?;
    let req = format!(
        "POST /ts2021 HTTP/1.1\r\nHost: {}\r\nUser-Agent: tsr\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\nX-Tailscale-Handshake: {}\r\nContent-Length: 0\r\n\r\n",
        host_header(server),
        base64::engine::general_purpose::STANDARD.encode(&init)
    );
    s.write_all(req.as_bytes()).await?;
    let (status, headers, mut leftover) = read_head(s.as_mut()).await?;
    if status != 101 {
        let body = read_body(s.as_mut(), &headers, leftover)
            .await
            .unwrap_or_default();
        bail!(
            "ts2021 upgrade failed: HTTP {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }

    // The handshake response follows the 101 on the same socket.
    while leftover.len() < noise::HEADER_LEN {
        read_more(s.as_mut(), &mut leftover).await?;
    }
    let want = noise::HEADER_LEN + u16::from_be_bytes([leftover[1], leftover[2]]) as usize;
    while leftover.len() < want {
        read_more(s.as_mut(), &mut leftover).await?;
    }
    let transport = hs.finish(&leftover[..want])?;
    leftover.drain(..want);
    tracing::debug!("noise handshake with control complete");

    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (early_tx, early_rx) = oneshot::channel();
    tokio::spawn(pump(s, transport, theirs, leftover, early_tx));
    Ok(NoiseConn {
        stream: ours,
        early: early_rx,
    })
}

async fn read_more(s: &mut dyn Stream, buf: &mut Vec<u8>) -> Result<()> {
    let mut chunk = [0u8; 4096];
    let n = s.read(&mut chunk).await?;
    ensure!(n > 0, "control connection closed during handshake");
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

/// Shuttle bytes between the Noise socket and the plaintext duplex.
async fn pump(
    sock: Box<dyn Stream>,
    t: Transport,
    plain: DuplexStream,
    leftover: Vec<u8>,
    early_tx: oneshot::Sender<EarlyNoise>,
) {
    let Transport { mut tx, mut rx, .. } = t;
    let (mut sock_r, mut sock_w) = tokio::io::split(sock);
    let (mut plain_r, mut plain_w) = tokio::io::split(plain);

    let writer = async move {
        let mut buf = vec![0u8; noise::MAX_PLAINTEXT_SIZE];
        loop {
            let n = plain_r.read(&mut buf).await?;
            if n == 0 {
                return anyhow::Ok(());
            }
            let frame = tx.seal_frame(&buf[..n])?;
            sock_w.write_all(&frame).await?;
        }
    };

    let reader = async move {
        let mut net = leftover;
        let mut chunk = vec![0u8; 16 * 1024];
        // Plaintext received before we know whether it starts with the early payload.
        let mut pending: Vec<u8> = Vec::new();
        let mut early_tx = Some(early_tx);
        loop {
            // Decode every complete frame in `net`.
            while net.len() >= noise::HEADER_LEN {
                let len = u16::from_be_bytes([net[1], net[2]]) as usize;
                if net.len() < noise::HEADER_LEN + len {
                    break;
                }
                let frame: Vec<u8> = net.drain(..noise::HEADER_LEN + len).collect();
                match frame[0] {
                    noise::MSG_RECORD => {}
                    noise::MSG_ERROR => {
                        bail!("control error: {}", String::from_utf8_lossy(&frame[3..]))
                    }
                    t => bail!("unexpected noise message type {t}"),
                }
                let pt = rx.open(&frame[noise::HEADER_LEN..])?;
                if early_tx.is_none() {
                    plain_w.write_all(&pt).await?;
                    continue;
                }
                pending.extend_from_slice(&pt);
                if pending.len() < EARLY_PAYLOAD_MAGIC.len() {
                    continue;
                }
                if &pending[..5] != EARLY_PAYLOAD_MAGIC {
                    // Old server: no early payload; everything is HTTP/2.
                    let _ = early_tx.take().unwrap().send(EarlyNoise::default());
                    plain_w.write_all(&pending).await?;
                    pending.clear();
                    continue;
                }
                if pending.len() < 9 {
                    continue;
                }
                let json_len = u32::from_be_bytes(pending[5..9].try_into().unwrap()) as usize;
                if pending.len() < 9 + json_len {
                    continue;
                }
                let early: EarlyNoise =
                    serde_json::from_slice(&pending[9..9 + json_len]).unwrap_or_default();
                tracing::debug!(?early, "early noise payload");
                let _ = early_tx.take().unwrap().send(early);
                plain_w.write_all(&pending[9 + json_len..]).await?;
                pending.clear();
            }
            let n = sock_r.read(&mut chunk).await?;
            if n == 0 {
                return anyhow::Ok(());
            }
            net.extend_from_slice(&chunk[..n]);
        }
    };

    tokio::select! {
        r = writer => if let Err(e) = r { tracing::warn!("control write: {e:#}") },
        r = reader => if let Err(e) = r { tracing::warn!("control read: {e:#}") },
    }
}
