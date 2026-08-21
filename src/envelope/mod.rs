//! VoiceChat Authenticated Envelope
//!
//! Versioned application envelope whose security-sensitive metadata is
//! cryptographically bound. Ciphertext produced for conversation A / device A
//! must not authenticate under conversation B / device B.
//!
//! Design rules:
//! - Strict canonical serialization (deterministic field order, no duplicates).
//! - Sensitive routing/application metadata is placed in AEAD associated data
//!   (or encrypted when transport requires confidentiality of that metadata).
//! - Parser is fail-closed: unknown critical fields, overflows, oversized
//!   payloads, invalid UTF-8, malformed lengths, unsupported versions → error.
//! - Continuous fuzzing of the parser is required.

use crate::primitives::error::PrimitiveError;

/// Current envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Maximum payload size (bytes) accepted by the parser.
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024; // 1 MiB

/// Maximum length for identifier strings / byte arrays.
pub const MAX_ID_LEN: usize = 128;

/// Cryptographic suite identifier (authenticated).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CryptoSuite {
    /// X25519 + ML-KEM-768 + Triple Ratchet + AES-256-GCM
    PqxdhTripleAes256Gcm = 1,
}

impl CryptoSuite {
    pub fn from_u8(v: u8) -> Result<Self, PrimitiveError> {
        match v {
            1 => Ok(Self::PqxdhTripleAes256Gcm),
            _ => Err(PrimitiveError::InvalidLength), // treat as unsupported
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Application payload type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    Text = 1,
    SyntheticVoice = 2,
    Edit = 3,
    Acknowledgement = 4,
}

impl PayloadType {
    pub fn from_u8(v: u8) -> Result<Self, PrimitiveError> {
        match v {
            1 => Ok(Self::Text),
            2 => Ok(Self::SyntheticVoice),
            3 => Ok(Self::Edit),
            4 => Ok(Self::Acknowledgement),
            _ => Err(PrimitiveError::InvalidLength),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Synthetic-voice specific metadata (bound when payload_type == SyntheticVoice).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticVoiceMeta {
    pub codec: String, // e.g. "opus"
    pub duration_ms: u32,
    pub payload_length: u32, // claimed length; must match actual payload
}

/// The application envelope. All security-sensitive fields are part of the
/// authenticated associated data (or encrypted) and therefore cannot be
/// altered without detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub protocol_version: u8,
    pub crypto_suite: CryptoSuite,
    pub conversation_id: Vec<u8>,
    pub sender_user_id: Vec<u8>,
    pub sender_device_id: Vec<u8>,
    pub recipient_user_id: Vec<u8>,
    pub recipient_device_id: Vec<u8>,
    pub message_id: Vec<u8>,
    pub message_type: u8,       // application-defined subtype
    pub sequence: u64,          // monotonic per conversation/device
    pub created_timestamp: u64, // Unix ms or application clock
    pub payload_type: PayloadType,
    pub synthetic_voice: Option<SyntheticVoiceMeta>,
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Canonical serialization used both for AEAD associated data and for
    /// the cleartext envelope when metadata is not encrypted.
    ///
    /// Format (all multi-byte integers little-endian):
    /// ```
    /// version:        u8
    /// suite:          u8
    /// conv_id_len:    u16
    /// conv_id:        [u8; conv_id_len]
    /// sender_uid_len: u16
    /// sender_uid:     [u8; ...]
    /// sender_did_len: u16
    /// sender_did:     [u8; ...]
    /// recip_uid_len:  u16
    /// recip_uid:      [u8; ...]
    /// recip_did_len:  u16
    /// recip_did:      [u8; ...]
    /// msg_id_len:     u16
    /// msg_id:         [u8; ...]
    /// message_type:   u8
    /// sequence:       u64
    /// timestamp:      u64
    /// payload_type:   u8
    /// [if SyntheticVoice]
    ///   codec_len:    u16
    ///   codec:        [u8; ...]   (UTF-8)
    ///   duration_ms:  u32
    ///   payload_len:  u32
    /// payload_len:    u32
    /// payload:        [u8; payload_len]
    /// ```
    ///
    /// Field order is fixed. Duplicate fields are impossible by construction.
    /// Unknown critical fields cannot appear because the format is closed.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PrimitiveError> {
        self.validate_limits()?;

        let mut out = Vec::with_capacity(256 + self.payload.len());
        out.push(self.protocol_version);
        out.push(self.crypto_suite.as_u8());

        write_bytes_u16(&mut out, &self.conversation_id)?;
        write_bytes_u16(&mut out, &self.sender_user_id)?;
        write_bytes_u16(&mut out, &self.sender_device_id)?;
        write_bytes_u16(&mut out, &self.recipient_user_id)?;
        write_bytes_u16(&mut out, &self.recipient_device_id)?;
        write_bytes_u16(&mut out, &self.message_id)?;

        out.push(self.message_type);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.created_timestamp.to_le_bytes());
        out.push(self.payload_type.as_u8());

        if self.payload_type == PayloadType::SyntheticVoice {
            let meta = self
                .synthetic_voice
                .as_ref()
                .ok_or(PrimitiveError::InvalidLength)?;
            if meta.codec.len() > MAX_ID_LEN || !meta.codec.is_ascii() {
                // require simple ASCII codec names for now
                return Err(PrimitiveError::InvalidLength);
            }
            write_bytes_u16(&mut out, meta.codec.as_bytes())?;
            out.extend_from_slice(&meta.duration_ms.to_le_bytes());
            out.extend_from_slice(&meta.payload_length.to_le_bytes());
            if meta.payload_length as usize != self.payload.len() {
                return Err(PrimitiveError::InvalidLength);
            }
        } else if self.synthetic_voice.is_some() {
            // synthetic_voice metadata present for non-voice payload → reject
            return Err(PrimitiveError::InvalidLength);
        }

        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(PrimitiveError::InvalidLength);
        }
        let plen = self.payload.len() as u32;
        out.extend_from_slice(&plen.to_le_bytes());
        out.extend_from_slice(&self.payload);

        Ok(out)
    }

    /// Parse a canonical envelope. Fail-closed on every malformed input.
    pub fn parse(data: &[u8]) -> Result<Self, PrimitiveError> {
        let mut i = 0;
        let version = read_u8(data, &mut i)?;
        if version != ENVELOPE_VERSION {
            return Err(PrimitiveError::InvalidLength); // unsupported version
        }
        let suite = CryptoSuite::from_u8(read_u8(data, &mut i)?)?;

        let conversation_id = read_bytes_u16(data, &mut i)?;
        let sender_user_id = read_bytes_u16(data, &mut i)?;
        let sender_device_id = read_bytes_u16(data, &mut i)?;
        let recipient_user_id = read_bytes_u16(data, &mut i)?;
        let recipient_device_id = read_bytes_u16(data, &mut i)?;
        let message_id = read_bytes_u16(data, &mut i)?;

        let message_type = read_u8(data, &mut i)?;
        let sequence = read_u64(data, &mut i)?;
        let created_timestamp = read_u64(data, &mut i)?;
        let payload_type = PayloadType::from_u8(read_u8(data, &mut i)?)?;

        let synthetic_voice = if payload_type == PayloadType::SyntheticVoice {
            let codec_bytes = read_bytes_u16(data, &mut i)?;
            let codec = std::str::from_utf8(&codec_bytes)
                .map_err(|_| PrimitiveError::InvalidLength)?
                .to_string();
            if !codec.is_ascii() || codec.len() > MAX_ID_LEN {
                return Err(PrimitiveError::InvalidLength);
            }
            let duration_ms = read_u32(data, &mut i)?;
            let payload_length = read_u32(data, &mut i)?;
            Some(SyntheticVoiceMeta {
                codec,
                duration_ms,
                payload_length,
            })
        } else {
            None
        };

        let payload_len = read_u32(data, &mut i)? as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(PrimitiveError::InvalidLength);
        }
        if i + payload_len != data.len() {
            // trailing data or truncated → reject
            return Err(PrimitiveError::InvalidLength);
        }
        let payload = data[i..i + payload_len].to_vec();

        if let Some(ref meta) = synthetic_voice {
            if meta.payload_length as usize != payload.len() {
                return Err(PrimitiveError::InvalidLength);
            }
        }

        let env = Self {
            protocol_version: version,
            crypto_suite: suite,
            conversation_id,
            sender_user_id,
            sender_device_id,
            recipient_user_id,
            recipient_device_id,
            message_id,
            message_type,
            sequence,
            created_timestamp,
            payload_type,
            synthetic_voice,
            payload,
        };
        env.validate_limits()?;
        Ok(env)
    }

    /// Produce the associated-data bytes that must be supplied to the AEAD.
    /// This binds every security-sensitive field.
    pub fn associated_data(&self) -> Result<Vec<u8>, PrimitiveError> {
        // For the current design the entire canonical encoding (excluding
        // the raw payload if it is large) can be used, or a compact AD
        // that omits the payload body. We bind the header fields strictly.
        // Policy: bind everything except the payload body itself (the
        // payload is the AEAD plaintext).
        let mut ad_env = self.clone();
        ad_env.payload = Vec::new(); // payload is plaintext, not AD
        ad_env.canonical_bytes()
    }

    fn validate_limits(&self) -> Result<(), PrimitiveError> {
        if self.protocol_version != ENVELOPE_VERSION {
            return Err(PrimitiveError::InvalidLength);
        }
        for id in [
            &self.conversation_id,
            &self.sender_user_id,
            &self.sender_device_id,
            &self.recipient_user_id,
            &self.recipient_device_id,
            &self.message_id,
        ] {
            if id.len() > MAX_ID_LEN {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Canonical helpers (strict, no overflow, no duplicate fields possible)
// ---------------------------------------------------------------------------

fn write_bytes_u16(out: &mut Vec<u8>, data: &[u8]) -> Result<(), PrimitiveError> {
    if data.len() > u16::MAX as usize || data.len() > MAX_ID_LEN {
        return Err(PrimitiveError::InvalidLength);
    }
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn read_u8(data: &[u8], i: &mut usize) -> Result<u8, PrimitiveError> {
    if *i >= data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let v = data[*i];
    *i += 1;
    Ok(v)
}

fn read_u16(data: &[u8], i: &mut usize) -> Result<u16, PrimitiveError> {
    if *i + 2 > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let v = u16::from_le_bytes(data[*i..*i + 2].try_into().unwrap());
    *i += 2;
    Ok(v)
}

fn read_u32(data: &[u8], i: &mut usize) -> Result<u32, PrimitiveError> {
    if *i + 4 > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let v = u32::from_le_bytes(data[*i..*i + 4].try_into().unwrap());
    *i += 4;
    Ok(v)
}

fn read_u64(data: &[u8], i: &mut usize) -> Result<u64, PrimitiveError> {
    if *i + 8 > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let v = u64::from_le_bytes(data[*i..*i + 8].try_into().unwrap());
    *i += 8;
    Ok(v)
}

fn read_bytes_u16(data: &[u8], i: &mut usize) -> Result<Vec<u8>, PrimitiveError> {
    let len = read_u16(data, i)? as usize;
    if len > MAX_ID_LEN || *i + len > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let v = data[*i..*i + len].to_vec();
    *i += len;
    Ok(v)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> Envelope {
        Envelope {
            protocol_version: ENVELOPE_VERSION,
            crypto_suite: CryptoSuite::PqxdhTripleAes256Gcm,
            conversation_id: b"conv-abc".to_vec(),
            sender_user_id: b"user-alice".to_vec(),
            sender_device_id: b"device-1".to_vec(),
            recipient_user_id: b"user-bob".to_vec(),
            recipient_device_id: b"device-9".to_vec(),
            message_id: b"msg-001".to_vec(),
            message_type: 0,
            sequence: 42,
            created_timestamp: 1_700_000_000_000,
            payload_type: PayloadType::Text,
            synthetic_voice: None,
            payload: b"hello voicechat".to_vec(),
        }
    }

    #[test]
    fn roundtrip_canonical() {
        let env = sample_envelope();
        let bytes = env.canonical_bytes().unwrap();
        let parsed = Envelope::parse(&bytes).unwrap();
        assert_eq!(env, parsed);
    }

    #[test]
    fn conversation_binding_prevents_move() {
        let mut env_a = sample_envelope();
        env_a.conversation_id = b"conversation-A".to_vec();
        let mut env_b = env_a.clone();
        env_b.conversation_id = b"conversation-B".to_vec();

        let ad_a = env_a.associated_data().unwrap();
        let ad_b = env_b.associated_data().unwrap();
        assert_ne!(
            ad_a, ad_b,
            "different conversations must produce different AD"
        );
    }

    #[test]
    fn device_binding_prevents_move() {
        let mut env = sample_envelope();
        let ad1 = env.associated_data().unwrap();
        env.recipient_device_id = b"device-OTHER".to_vec();
        let ad2 = env.associated_data().unwrap();
        assert_ne!(
            ad1, ad2,
            "different recipient devices must produce different AD"
        );
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut bytes = sample_envelope().canonical_bytes().unwrap();
        bytes[0] = 99; // unknown version
        assert!(Envelope::parse(&bytes).is_err());
    }

    #[test]
    fn oversized_payload_rejected() {
        let mut env = sample_envelope();
        env.payload = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert!(env.canonical_bytes().is_err());
    }

    #[test]
    fn truncated_input_rejected() {
        let bytes = sample_envelope().canonical_bytes().unwrap();
        assert!(Envelope::parse(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn trailing_garbage_rejected() {
        let mut bytes = sample_envelope().canonical_bytes().unwrap();
        bytes.push(0xff);
        assert!(Envelope::parse(&bytes).is_err());
    }

    #[test]
    fn synthetic_voice_roundtrip() {
        let env = Envelope {
            protocol_version: ENVELOPE_VERSION,
            crypto_suite: CryptoSuite::PqxdhTripleAes256Gcm,
            conversation_id: b"c".to_vec(),
            sender_user_id: b"a".to_vec(),
            sender_device_id: b"d1".to_vec(),
            recipient_user_id: b"b".to_vec(),
            recipient_device_id: b"d2".to_vec(),
            message_id: b"m".to_vec(),
            message_type: 0,
            sequence: 1,
            created_timestamp: 100,
            payload_type: PayloadType::SyntheticVoice,
            synthetic_voice: Some(SyntheticVoiceMeta {
                codec: "opus".into(),
                duration_ms: 1500,
                payload_length: 5,
            }),
            payload: b"audio".to_vec(),
        };
        let bytes = env.canonical_bytes().unwrap();
        let parsed = Envelope::parse(&bytes).unwrap();
        assert_eq!(env, parsed);
    }

    #[test]
    fn synthetic_voice_length_mismatch_rejected() {
        let env = Envelope {
            protocol_version: ENVELOPE_VERSION,
            crypto_suite: CryptoSuite::PqxdhTripleAes256Gcm,
            conversation_id: b"c".to_vec(),
            sender_user_id: b"a".to_vec(),
            sender_device_id: b"d1".to_vec(),
            recipient_user_id: b"b".to_vec(),
            recipient_device_id: b"d2".to_vec(),
            message_id: b"m".to_vec(),
            message_type: 0,
            sequence: 1,
            created_timestamp: 100,
            payload_type: PayloadType::SyntheticVoice,
            synthetic_voice: Some(SyntheticVoiceMeta {
                codec: "opus".into(),
                duration_ms: 1500,
                payload_length: 99, // wrong
            }),
            payload: b"audio".to_vec(),
        };
        assert!(env.canonical_bytes().is_err());
    }

    #[test]
    fn associated_data_stable_for_same_envelope() {
        let env = sample_envelope();
        let ad1 = env.associated_data().unwrap();
        let ad2 = env.associated_data().unwrap();
        assert_eq!(ad1, ad2);
    }
}
