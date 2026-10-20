//! Key types. Tailscale uses Curve25519 keys everywhere and serialises the
//! public halves as `prefix:` + lowercase hex.

use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use x25519_dalek::{PublicKey, StaticSecret};

macro_rules! public_key {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn is_zero(&self) -> bool {
                self.0 == [0u8; 32]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Short form, like Tailscale's ShortString().
                write!(f, "[{}]", &hex::encode(self.0)[..5])
            }
        }

        impl FromStr for $name {
            type Err = anyhow::Error;
            fn from_str(s: &str) -> Result<Self> {
                let hex_part = s
                    .strip_prefix($prefix)
                    .with_context(|| format!("key {s:?} lacks prefix {}", $prefix))?;
                let bytes = hex::decode(hex_part)?;
                if bytes.len() != 32 {
                    bail!("key {s:?} is not 32 bytes");
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                Ok(Self(k))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                if s.is_empty() {
                    return Ok(Self::default());
                }
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

public_key!(MachinePublic, "mkey:");
public_key!(NodePublic, "nodekey:");
public_key!(DiscoPublic, "discokey:");

/// A Curve25519 private key. The same type backs machine, node and disco keys;
/// the role is decided by where it is used.
#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateKey(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl PrivateKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        // Clamp like Tailscale does, so the stored bytes are canonical.
        k[0] &= 248;
        k[31] = (k[31] & 127) | 64;
        Self(k)
    }

    pub fn secret(&self) -> StaticSecret {
        StaticSecret::from(self.0)
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        PublicKey::from(&self.secret()).to_bytes()
    }

    pub fn machine_public(&self) -> MachinePublic {
        MachinePublic(self.public_bytes())
    }
    pub fn node_public(&self) -> NodePublic {
        NodePublic(self.public_bytes())
    }
    pub fn disco_public(&self) -> DiscoPublic {
        DiscoPublic(self.public_bytes())
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("want 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trip() {
        let k = PrivateKey::generate().node_public();
        let s = k.to_string();
        assert!(s.starts_with("nodekey:"));
        assert_eq!(s.parse::<NodePublic>().unwrap(), k);
        assert!(s.parse::<MachinePublic>().is_err());
    }
}
