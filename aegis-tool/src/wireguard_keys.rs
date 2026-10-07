use std::{fs, path::Path};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone)]
pub(crate) struct Keypair {
    pub private_key: String,
    pub public_key: String,
}

impl Keypair {
    pub fn generate() -> Result<Self> {
        Self::from_private_key(&STANDARD.encode(StaticSecret::random().to_bytes()))
    }

    pub fn from_private_key(value: &str) -> Result<Self> {
        let private_key = aegis_dto::normalize_wireguard_key(value)?;
        let bytes: [u8; 32] = STANDARD
            .decode(&private_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("WireGuard key must contain 32 bytes"))?;
        let public_key = STANDARD.encode(PublicKey::from(&StaticSecret::from(bytes)).to_bytes());
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn ensure(private: &Path, public: &Path) -> Result<Self> {
        let key = match fs::read_to_string(private) {
            Ok(value) => Self::from_private_key(&value)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    !public.exists(),
                    "WireGuard public key exists without its private key; explicit repair is required"
                );
                let key = Self::generate()?;
                capulus::store::atomic_write(
                    private,
                    format!("{}\n", key.private_key).as_bytes(),
                    Some(0o600),
                    Some(0o755),
                )?;
                key
            }
            Err(error) => return Err(error).context("read WireGuard private key"),
        };
        match fs::read_to_string(public) {
            Ok(value) => ensure!(
                value.trim() == key.public_key,
                "WireGuard public and private keys disagree"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                capulus::store::atomic_write(
                    public,
                    format!("{}\n", key.public_key).as_bytes(),
                    Some(0o644),
                    Some(0o755),
                )?;
            }
            Err(error) => return Err(error).context("read WireGuard public key"),
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_rfc7748_public_key() {
        let private = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let expected = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        assert_eq!(
            Keypair::from_private_key(&STANDARD.encode(private))
                .unwrap()
                .public_key,
            STANDARD.encode(expected)
        );
    }

    #[test]
    fn interruption_after_private_key_write_preserves_identity() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("private");
        let public = dir.path().join("public");
        let key = Keypair::generate().unwrap();
        fs::write(&private, &key.private_key).unwrap();
        assert_eq!(
            Keypair::ensure(&private, &public).unwrap().public_key,
            key.public_key
        );
        fs::write(&public, "wrong").unwrap();
        assert!(Keypair::ensure(&private, &public).is_err());
        assert_eq!(fs::read_to_string(private).unwrap(), key.private_key);
    }
}
