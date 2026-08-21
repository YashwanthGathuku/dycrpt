//! Ratcheted authenticator from ML-KEM Braid Rev 1 §2.4.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{hkdf_extract_expand, hmac_sha256, LABELS};
use crate::primitives::zeroizing::ct_eq;

const MAC_SIZE: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Authenticator {
    root_key: [u8; 32],
    mac_key: [u8; 32],
}

impl Authenticator {
    pub fn init(epoch: u64, key: &[u8; 32]) -> Result<Self, PrimitiveError> {
        let mut a = Self {
            root_key: [0u8; 32],
            mac_key: [0u8; 32],
        };
        a.update(epoch, key)?;
        Ok(a)
    }

    pub fn update(&mut self, epoch: u64, key: &[u8; 32]) -> Result<(), PrimitiveError> {
        // KDF_AUTH: ikm = update_key, salt = root_key,
        // info = PROTOCOL_INFO || ":Authenticator Update" || ToBytes(epoch)
        let mut info = LABELS::BRAID_PROTOCOL_INFO.to_vec();
        info.extend_from_slice(b":Authenticator Update");
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut okm = [0u8; 64];
        hkdf_extract_expand(Some(&self.root_key), key, &info, &mut okm)?;
        self.root_key.copy_from_slice(&okm[..32]);
        self.mac_key.copy_from_slice(&okm[32..]);
        Ok(())
    }

    pub fn mac_hdr(&self, epoch: u64, hdr: &[u8]) -> [u8; MAC_SIZE] {
        let mut m = LABELS::BRAID_PROTOCOL_INFO.to_vec();
        m.extend_from_slice(b":ekheader");
        m.extend_from_slice(&epoch.to_be_bytes());
        m.extend_from_slice(hdr);
        hmac_sha256(&self.mac_key, &m)
    }

    pub fn mac_ct(&self, epoch: u64, ct: &[u8]) -> [u8; MAC_SIZE] {
        let mut m = LABELS::BRAID_PROTOCOL_INFO.to_vec();
        m.extend_from_slice(b":ciphertext");
        m.extend_from_slice(&epoch.to_be_bytes());
        m.extend_from_slice(ct);
        hmac_sha256(&self.mac_key, &m)
    }

    pub fn vfy_hdr(&self, epoch: u64, hdr: &[u8], expected: &[u8]) -> Result<(), PrimitiveError> {
        let got = self.mac_hdr(epoch, hdr);
        if expected.len() != MAC_SIZE || !ct_eq(&got, expected) {
            return Err(PrimitiveError::AeadAuthFailed);
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; 64] {
        let mut o = [0u8; 64];
        o[..32].copy_from_slice(&self.root_key);
        o[32..].copy_from_slice(&self.mac_key);
        o
    }

    pub fn decode(bytes: &[u8; 64]) -> Self {
        let mut root_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        root_key.copy_from_slice(&bytes[..32]);
        mac_key.copy_from_slice(&bytes[32..]);
        Self { root_key, mac_key }
    }

    pub fn vfy_ct(&self, epoch: u64, ct: &[u8], expected: &[u8]) -> Result<(), PrimitiveError> {
        let got = self.mac_ct(epoch, ct);
        if expected.len() != MAC_SIZE || !ct_eq(&got, expected) {
            return Err(PrimitiveError::AeadAuthFailed);
        }
        Ok(())
    }
}

/// KDF_OK(shared_secret, epoch) — Braid §2.2.
pub fn kdf_ok(shared_secret: &[u8], epoch: u64) -> Result<[u8; 32], PrimitiveError> {
    let salt = [0u8; 32];
    let mut info = LABELS::BRAID_PROTOCOL_INFO.to_vec();
    info.extend_from_slice(b":SCKA Key");
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut out = [0u8; 32];
    hkdf_extract_expand(Some(&salt), shared_secret, &info, &mut out)?;
    Ok(out)
}
