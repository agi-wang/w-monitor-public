//! Client-held Ed25519 keys and origin-bound report signatures.
use anyhow::{bail, Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SigningKey {
    pair: Ed25519KeyPair,
}
impl SigningKey {
    pub fn generate() -> Result<(Self, String)> {
        let mut seed = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| anyhow::anyhow!("Secure random generation failed"))?;
        let encoded = hex::encode(seed);
        Ok((Self::from_seed(&encoded)?, encoded))
    }
    pub fn from_seed(seed: &str) -> Result<Self> {
        if seed.len() != 64 {
            bail!("Invalid private key length");
        }
        let raw = hex::decode(seed).context("Invalid private key encoding")?;
        let pair = Ed25519KeyPair::from_seed_unchecked(&raw)
            .map_err(|_| anyhow::anyhow!("Invalid Ed25519 private key"))?;
        Ok(Self { pair })
    }
    pub fn public(&self) -> String {
        hex::encode(self.pair.public_key().as_ref())
    }
    pub fn sign(&self, message: &str) -> String {
        hex::encode(self.pair.sign(message.as_bytes()).as_ref())
    }
    pub fn headers(
        &self,
        endpoint: &url::Url,
        token: &str,
        body: &[u8],
        compressed: bool,
        metrics: bool,
    ) -> Result<[(String, String); 4]> {
        static LAST: AtomicU64 = AtomicU64::new(0);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let old = LAST
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                Some(now.max(value + 1))
            })
            .unwrap();
        let timestamp = now.max(old + 1).to_string();
        let mut nonce = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("Secure random generation failed"))?;
        let nonce = hex::encode(nonce);
        let message = [
            "wm-device-v1",
            &endpoint.origin().ascii_serialization(),
            "POST",
            endpoint.path(),
            if metrics { "metrics" } else { "full" },
            if compressed { "gzip" } else { "identity" },
            &hex::encode(Sha256::digest(token.as_bytes())),
            &timestamp,
            &nonce,
            &hex::encode(Sha256::digest(body)),
        ]
        .join("\n");
        Ok([
            ("X-WM-Public-Key".into(), self.public()),
            ("X-WM-Timestamp".into(), timestamp),
            ("X-WM-Nonce".into(), nonce),
            ("X-WM-Signature".into(), self.sign(&message)),
        ])
    }
}
