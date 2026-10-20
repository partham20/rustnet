//! Tailscale's "controlbase" protocol: a Noise IK handshake followed by a
//! framed, encrypted record stream.
//!
//! Wire format (all lengths big-endian):
//!
//! ```text
//! initiation: [u16 protocol version][u8 type=1][u16 len=96][32 e][48 enc(s)][16 tag]
//! response:   [u8 type=2][u16 len=48][32 e][16 tag]
//! record:     [u8 type=4][u16 len][ciphertext]
//! error:      [u8 type=3][u16 len][utf-8 message]
//! ```
//!
//! Record nonces are 12 bytes with a 64-bit *big-endian* counter in the last
//! 8 bytes. Standard Noise uses little-endian, which is why we don't use a
//! general-purpose Noise crate here.

use anyhow::{bail, ensure, Result};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::SimpleHkdf;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::keys::{MachinePublic, PrivateKey};

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE_PREFIX: &str = "Tailscale Control Protocol v";

pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_ERROR: u8 = 3;
pub const MSG_RECORD: u8 = 4;

pub const HEADER_LEN: usize = 3;
pub const TAG_LEN: usize = 16;
/// Largest frame (header included) either side will send or accept.
pub const MAX_MESSAGE_SIZE: usize = 4096;
pub const MAX_PLAINTEXT_SIZE: usize = MAX_MESSAGE_SIZE - HEADER_LEN - TAG_LEN;

pub const INITIATION_LEN: usize = 2 + HEADER_LEN + 32 + 48 + TAG_LEN;
pub const RESPONSE_LEN: usize = HEADER_LEN + 32 + TAG_LEN;

fn blake2s(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = SimpleHkdf::<Blake2s256>::new(Some(ck), ikm);
    let mut out = [0u8; 64];
    hk.expand(&[], &mut out)
        .expect("64 bytes is a valid HKDF length");
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}

struct SymmetricState {
    h: [u8; 32],
    ck: [u8; 32],
}

impl SymmetricState {
    fn new() -> Self {
        // Protocol name is longer than 32 bytes, so h = HASH(name).
        let h = blake2s(&[PROTOCOL_NAME]);
        Self { h, ck: h }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = blake2s(&[&self.h, data]);
    }

    /// DH, then mix the result into the chaining key. Returns a one-shot key.
    fn mix_dh(&mut self, private: &StaticSecret, public: &[u8; 32]) -> Result<[u8; 32]> {
        let shared = private.diffie_hellman(&PublicKey::from(*public));
        ensure!(shared.was_contributory(), "non-contributory DH result");
        let (ck, k) = hkdf2(&self.ck, shared.as_bytes());
        self.ck = ck;
        Ok(k)
    }

    fn encrypt_and_hash(&mut self, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let ct = ChaCha20Poly1305::new(key.into())
            .encrypt(
                &Nonce::default(),
                Payload {
                    msg: plaintext,
                    aad: &self.h,
                },
            )
            .expect("chacha20poly1305 encryption cannot fail");
        self.mix_hash(&ct);
        ct
    }

    fn decrypt_and_hash(&mut self, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let pt = ChaCha20Poly1305::new(key.into())
            .decrypt(
                &Nonce::default(),
                Payload {
                    msg: ciphertext,
                    aad: &self.h,
                },
            )
            .map_err(|_| anyhow::anyhow!("handshake decryption failed"))?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    fn split(&self) -> ([u8; 32], [u8; 32]) {
        hkdf2(&self.ck, &[])
    }
}

/// One direction of the record layer.
pub struct CipherState {
    aead: ChaCha20Poly1305,
    n: u64,
}

impl CipherState {
    fn new(key: [u8; 32]) -> Self {
        Self {
            aead: ChaCha20Poly1305::new(&key.into()),
            n: 0,
        }
    }

    fn next_nonce(&mut self) -> Result<Nonce> {
        ensure!(self.n != u64::MAX, "nonce space exhausted");
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.n.to_be_bytes());
        self.n += 1;
        Ok(nonce.into())
    }

    /// Encrypt `plaintext` into a complete record frame.
    pub fn seal_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(plaintext.len() <= MAX_PLAINTEXT_SIZE, "record too large");
        let nonce = self.next_nonce()?;
        let ct = self
            .aead
            .encrypt(&nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("encrypt failed"))?;
        let mut frame = Vec::with_capacity(HEADER_LEN + ct.len());
        frame.push(MSG_RECORD);
        frame.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        frame.extend_from_slice(&ct);
        Ok(frame)
    }

    /// Decrypt the payload of a record frame (header already stripped).
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce()?;
        self.aead
            .decrypt(&nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("record decryption failed"))
    }
}

/// Established session keys.
pub struct Transport {
    pub tx: CipherState,
    pub rx: CipherState,
    pub handshake_hash: [u8; 32],
}

/// Client (initiator) side of the handshake.
pub struct ClientHandshake {
    state: SymmetricState,
    ephemeral: StaticSecret,
    machine: StaticSecret,
}

impl ClientHandshake {
    /// Build the initiation message. Returns the handshake state and the bytes
    /// to send (they go base64-encoded into the `X-Tailscale-Handshake` header).
    pub fn start(
        machine_key: &PrivateKey,
        control_key: &MachinePublic,
        protocol_version: u16,
    ) -> Result<(Self, Vec<u8>)> {
        let mut s = SymmetricState::new();
        s.mix_hash(format!("{PROLOGUE_PREFIX}{protocol_version}").as_bytes());
        // <- s
        s.mix_hash(&control_key.0);

        // -> e, es, s, ss
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let e_pub = PublicKey::from(&ephemeral).to_bytes();
        s.mix_hash(&e_pub);
        let k = s.mix_dh(&ephemeral, &control_key.0)?;
        let enc_static = s.encrypt_and_hash(&k, &machine_key.public_bytes());
        let machine = machine_key.secret();
        let k = s.mix_dh(&machine, &control_key.0)?;
        let tag = s.encrypt_and_hash(&k, &[]);

        let mut msg = Vec::with_capacity(INITIATION_LEN);
        msg.extend_from_slice(&protocol_version.to_be_bytes());
        msg.push(MSG_INITIATION);
        msg.extend_from_slice(&((32 + 48 + TAG_LEN) as u16).to_be_bytes());
        msg.extend_from_slice(&e_pub);
        msg.extend_from_slice(&enc_static);
        msg.extend_from_slice(&tag);
        debug_assert_eq!(msg.len(), INITIATION_LEN);

        Ok((
            Self {
                state: s,
                ephemeral,
                machine,
            },
            msg,
        ))
    }

    /// Consume the server's response frame and derive transport keys.
    pub fn finish(mut self, resp: &[u8]) -> Result<Transport> {
        ensure!(resp.len() >= HEADER_LEN, "short handshake response");
        let len = u16::from_be_bytes([resp[1], resp[2]]) as usize;
        if resp[0] == MSG_ERROR {
            let msg =
                String::from_utf8_lossy(&resp[HEADER_LEN..(HEADER_LEN + len).min(resp.len())]);
            bail!("control server rejected handshake: {msg}");
        }
        ensure!(
            resp[0] == MSG_RESPONSE,
            "unexpected handshake message type {}",
            resp[0]
        );
        ensure!(
            resp.len() == RESPONSE_LEN && len == 32 + TAG_LEN,
            "bad handshake response length"
        );

        // <- e, ee, se
        let mut re = [0u8; 32];
        re.copy_from_slice(&resp[3..35]);
        self.state.mix_hash(&re);
        self.state.mix_dh(&self.ephemeral, &re)?;
        let k = self.state.mix_dh(&self.machine, &re)?;
        self.state.decrypt_and_hash(&k, &resp[35..])?;

        let (k1, k2) = self.state.split();
        Ok(Transport {
            tx: CipherState::new(k1),
            rx: CipherState::new(k2),
            handshake_hash: self.state.h,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal responder, mirroring Tailscale's controlbase.Server, used to
    /// check our initiator against the spec end to end.
    fn respond(control: &PrivateKey, init: &[u8]) -> (Vec<u8>, Transport, [u8; 32]) {
        let version = u16::from_be_bytes([init[0], init[1]]);
        assert_eq!(init[2], MSG_INITIATION);
        let body = &init[5..];
        let mut s = SymmetricState::new();
        s.mix_hash(format!("{PROLOGUE_PREFIX}{version}").as_bytes());
        s.mix_hash(&control.public_bytes());
        let mut ie = [0u8; 32];
        ie.copy_from_slice(&body[..32]);
        s.mix_hash(&ie);
        let k = s.mix_dh(&control.secret(), &ie).unwrap();
        let ms: [u8; 32] = s
            .decrypt_and_hash(&k, &body[32..80])
            .unwrap()
            .try_into()
            .unwrap();
        let k = s.mix_dh(&control.secret(), &ms).unwrap();
        s.decrypt_and_hash(&k, &body[80..]).unwrap();

        let e = StaticSecret::random_from_rng(OsRng);
        let e_pub = PublicKey::from(&e).to_bytes();
        s.mix_hash(&e_pub);
        s.mix_dh(&e, &ie).unwrap();
        let k = s.mix_dh(&e, &ms).unwrap();
        let tag = s.encrypt_and_hash(&k, &[]);
        let mut resp = vec![MSG_RESPONSE, 0, 48];
        resp.extend_from_slice(&e_pub);
        resp.extend_from_slice(&tag);
        let (k1, k2) = s.split();
        (
            resp,
            Transport {
                tx: CipherState::new(k2),
                rx: CipherState::new(k1),
                handshake_hash: s.h,
            },
            ms,
        )
    }

    #[test]
    fn handshake_and_records() {
        let machine = PrivateKey::generate();
        let control = PrivateKey::generate();
        let (hs, init) = ClientHandshake::start(&machine, &control.machine_public(), 106).unwrap();
        assert_eq!(init.len(), INITIATION_LEN);
        let (resp, mut server, seen_machine) = respond(&control, &init);
        assert_eq!(seen_machine, machine.public_bytes());
        let mut client = hs.finish(&resp).unwrap();
        assert_eq!(client.handshake_hash, server.handshake_hash);

        for i in 0..3u8 {
            let f = client.tx.seal_frame(&[i; 100]).unwrap();
            assert_eq!(server.rx.open(&f[3..]).unwrap(), vec![i; 100]);
            let f = server.tx.seal_frame(b"pong").unwrap();
            assert_eq!(client.rx.open(&f[3..]).unwrap(), b"pong");
        }
    }

    #[test]
    fn nonce_is_big_endian() {
        let mut c = CipherState::new([7; 32]);
        c.n = 0x0102;
        let n = c.next_nonce().unwrap();
        assert_eq!(&n[..], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2]);
    }
}
