//! HTTP/2 requests to the control server over the ts2021 Noise channel.

use anyhow::{bail, Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use h2::client::SendRequest;
use h2::RecvStream;
use serde::Serialize;
use url::Url;

use crate::dial::{self, EarlyNoise};
use crate::keys::PrivateKey;
use crate::tailcfg::{MapRequest, MapResponse, RegisterRequest, RegisterResponse};
use crate::CAPABILITY_VERSION;

pub struct ControlClient {
    h2: SendRequest<Bytes>,
    authority: String,
    pub early: EarlyNoise,
}

impl ControlClient {
    pub async fn connect(server: &Url, machine_key: &PrivateKey) -> Result<Self> {
        let control_key = dial::fetch_server_key(server, CAPABILITY_VERSION)
            .await
            .context("fetching control server key")?;
        tracing::info!(%control_key, "control server key");
        let conn = dial::dial_ts2021(server, machine_key, &control_key, CAPABILITY_VERSION).await?;
        let (h2, connection) = h2::client::Builder::new()
            .initial_window_size(4 << 20)
            .initial_connection_window_size(4 << 20)
            .handshake(conn.stream)
            .await
            .context("HTTP/2 handshake over noise")?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::warn!("control HTTP/2 connection ended: {e}");
            }
        });
        let early = conn.early.await.unwrap_or_default();
        Ok(Self {
            h2,
            authority: server.host_str().unwrap_or("control").to_string(),
            early,
        })
    }

    async fn post_json<T: Serialize>(&mut self, path: &str, body: &T) -> Result<RecvStream> {
        let body = Bytes::from(serde_json::to_vec(body)?);
        let req = http::Request::post(format!("http://{}{}", self.authority, path))
            .header("content-type", "application/json")
            .body(())?;
        let mut send = self.h2.clone().ready().await?;
        let (resp, mut stream) = send.send_request(req, false)?;
        stream.send_data(body, true)?;
        let resp = resp.await.with_context(|| format!("POST {path}"))?;
        let status = resp.status();
        let mut recv = resp.into_body();
        if !status.is_success() {
            let body = read_all(&mut recv).await.unwrap_or_default();
            bail!(
                "POST {path}: HTTP {status}: {}",
                String::from_utf8_lossy(&body).trim()
            );
        }
        Ok(recv)
    }

    pub async fn register(&mut self, req: &RegisterRequest) -> Result<RegisterResponse> {
        let mut body = self.post_json("/machine/register", req).await?;
        let bytes = read_all(&mut body).await?;
        serde_json::from_slice(&bytes).context("parsing RegisterResponse")
    }

    /// Start a map poll. With `req.stream` set, the server keeps the response
    /// open and sends a new [`MapResponse`] whenever the netmap changes.
    pub async fn map(&mut self, req: &MapRequest) -> Result<MapStream> {
        if !req.compress.is_empty() {
            bail!("compressed map responses are not supported");
        }
        let body = self.post_json("/machine/map", req).await?;
        Ok(MapStream {
            body,
            buf: BytesMut::new(),
        })
    }
}

async fn read_all(body: &mut RecvStream) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Map responses are framed as `[u32 little-endian length][JSON]`.
pub struct MapStream {
    body: RecvStream,
    buf: BytesMut,
}

impl MapStream {
    pub async fn next(&mut self) -> Result<Option<MapResponse>> {
        loop {
            if self.buf.len() >= 4 {
                let len = u32::from_le_bytes(self.buf[..4].try_into().unwrap()) as usize;
                if self.buf.len() >= 4 + len {
                    self.buf.advance(4);
                    let msg = self.buf.split_to(len);
                    tracing::trace!("map response: {}", String::from_utf8_lossy(&msg));
                    return Ok(Some(
                        serde_json::from_slice(&msg).context("parsing MapResponse")?,
                    ));
                }
            }
            match self.body.data().await {
                Some(chunk) => {
                    let chunk = chunk?;
                    let _ = self.body.flow_control().release_capacity(chunk.len());
                    self.buf.extend_from_slice(&chunk);
                }
                None => return Ok(None),
            }
        }
    }
}
