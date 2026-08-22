//! Protocol version and cipher-suite / profile policy.
//!
//! Default advertised preference is ClassicalV1. Hybrid and header-encryption
//! are compiled when their features are on, but are not auto-selected.
//!
//! Protocol v2 is intentionally wire-incompatible with the original prototype:
//! it authenticates protocol/profile/session-routing metadata and separates the
//! local session handle from the shared network session tag. Existing v1 live
//! sessions must be re-handshaken rather than silently upgraded.

use crate::primitives::error::PrimitiveError;

pub const PROTOCOL_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CryptoProfile {
    ClassicalV1 = 1,
    #[cfg(feature = "header-encrypt")]
    ClassicalHeV1 = 2,
    #[cfg(feature = "hybrid")]
    HybridPqV1 = 3,
}

impl CryptoProfile {
    pub fn from_u8(v: u8) -> Result<Self, PrimitiveError> {
        match v {
            1 => Ok(Self::ClassicalV1),
            #[cfg(feature = "header-encrypt")]
            2 => Ok(Self::ClassicalHeV1),
            #[cfg(feature = "hybrid")]
            3 => Ok(Self::HybridPqV1),
            _ => Err(PrimitiveError::InvalidLength),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn is_hybrid(self) -> bool {
        #[cfg(feature = "hybrid")]
        {
            matches!(self, Self::HybridPqV1)
        }
        #[cfg(not(feature = "hybrid"))]
        {
            let _ = self;
            false
        }
    }

    pub fn uses_header_encryption(self) -> bool {
        #[cfg(feature = "header-encrypt")]
        {
            matches!(self, Self::ClassicalHeV1)
        }
        #[cfg(not(feature = "header-encrypt"))]
        {
            let _ = self;
            false
        }
    }
}

pub fn available_profiles() -> Vec<CryptoProfile> {
    let mut v = PROFILE_PREFERENCE.to_vec();
    #[cfg(feature = "header-encrypt")]
    {
        if !v.contains(&CryptoProfile::ClassicalHeV1) {
            v.push(CryptoProfile::ClassicalHeV1);
        }
    }
    #[cfg(feature = "hybrid")]
    {
        if !v.contains(&CryptoProfile::HybridPqV1) {
            v.push(CryptoProfile::HybridPqV1);
        }
    }
    v
}

/// Default advertised preference: classical only.
/// Hybrid is experimental until an independent review of Encaps1/Braid.
pub const PROFILE_PREFERENCE: &[CryptoProfile] = &[CryptoProfile::ClassicalV1];

pub fn select_profile(
    local: &[CryptoProfile],
    remote: &[CryptoProfile],
) -> Result<CryptoProfile, PrimitiveError> {
    for preferred in PROFILE_PREFERENCE {
        if local.contains(preferred) && remote.contains(preferred) {
            return Ok(*preferred);
        }
    }
    Err(PrimitiveError::InvalidLength)
}

pub fn enforce_profile(
    expected: CryptoProfile,
    actual: CryptoProfile,
) -> Result<(), PrimitiveError> {
    if expected != actual {
        return Err(PrimitiveError::InvalidLength);
    }
    Ok(())
}

pub fn version_binding_bytes() -> [u8; 2] {
    PROTOCOL_VERSION.to_le_bytes()
}

pub use CryptoProfile as CryptoSuite;
pub const SUITE_PREFERENCE: &[CryptoProfile] = PROFILE_PREFERENCE;

pub fn select_suite(
    local: &[CryptoProfile],
    remote: &[CryptoProfile],
) -> Result<CryptoProfile, PrimitiveError> {
    select_profile(local, remote)
}

pub fn enforce_suite(expected: CryptoProfile, actual: CryptoProfile) -> Result<(), PrimitiveError> {
    enforce_profile(expected, actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_hardened_v2() {
        assert_eq!(PROTOCOL_VERSION, 2);
    }

    #[test]
    fn default_peers_select_classical() {
        let got = select_profile(PROFILE_PREFERENCE, PROFILE_PREFERENCE).unwrap();
        assert_eq!(got, CryptoProfile::ClassicalV1);
        assert!(available_profiles().contains(&CryptoProfile::ClassicalV1));
    }

    #[test]
    fn classical_only_peer_is_not_upgraded() {
        let classical = [CryptoProfile::ClassicalV1];
        assert_eq!(
            select_profile(PROFILE_PREFERENCE, &classical).unwrap(),
            CryptoProfile::ClassicalV1
        );
        assert_eq!(
            select_profile(&classical, PROFILE_PREFERENCE).unwrap(),
            CryptoProfile::ClassicalV1
        );
    }

    #[test]
    fn no_silent_downgrade() {
        assert!(enforce_profile(CryptoProfile::ClassicalV1, CryptoProfile::ClassicalV1).is_ok());
        #[cfg(feature = "hybrid")]
        assert!(enforce_profile(CryptoProfile::HybridPqV1, CryptoProfile::ClassicalV1).is_err());
    }
}
