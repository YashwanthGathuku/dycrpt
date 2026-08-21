//! Cryptographic primitive abstractions.
//!
//! Thin wrappers around audited libraries, plus FIPS 203 Encaps1/Encaps2
//! (Braid incremental KEM) implemented from the public standard.

pub mod aead;
pub mod encoding;
pub mod error;
pub mod kdf;
pub mod kem;
pub mod mlkem_inc;
pub mod random;
pub mod signature;
pub mod x25519;
pub mod xeddsa;
pub mod zeroizing;

pub use error::PrimitiveError;
pub use kdf::{hkdf_expand, hkdf_extract_expand, pqxdh_kdf, LABELS};
pub use random::fill_random;
pub use zeroizing::{
    ct_eq, secure_zero, secure_zero_32, with_secret_32, SecretBytes, SecretBytes32, ZeroizingScope,
};
