//! VoiceChat Authenticated Envelope
//!
//! Versioned application envelope whose security-sensitive metadata is
//! cryptographically bound. Ciphertext produced for conversation A / device A
//! must not authenticate under conversation B / device B.
//!
//! Design rules:
//! - Strict canonical serialization (deterministic field order, no duplicates).
//! - Sensitive routing/application metadata is placed in AEAD associated data.
//! - The payload body is AEAD plaintext, while its exact length is authenticated.
//! - Parser is fail-closed: unknown critical fields, overflows, oversized
//!   payloads, invalid UTF-8, malformed lengths, unsupported versions → error.

use crate::primitives::error::PrimitiveError;

pub const ENVELOPE_VERSION: u8 = 1;
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024;
pub const MAX_ID_LEN: usize = 128;
const ENVELOPE_AD_DOMAIN: &[u8] = b"VCENV-AD-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CryptoSuite {
    /// X25519 + ML-KEM-768 + Triple Ratchet + AES-256-GCM.
    PqxdhTripleAes256Gcm = 1,
}

impl CryptoSuite {
    pub fn from_u8(v: u8) -> Result<Self, PrimitiveError> {
        match v {
            1 => Ok(Self::PqxdhTripleAes256Gcm),
            _ => Err(PrimitiveError::InvalidLength),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticVoiceMeta {
    pub codec: String,
    pub duration_ms: u32,
    pub payload_length: u32,
}

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
    pub message_type: u8,
    pub sequence: u64,
    pub created_timestamp: u64,
    pub payload_type: PayloadType,
    pub synthetic_voice: Option<SyntheticVoiceMeta>,
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Canonical full-envelope serialization.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PrimitiveError> {
        self.validate_limits()?;
        self.validate_payload_metadata()?;
        let mut out = Vec::with_capacity(256 + self.payload.len());
        self.write_authenticated_metadata(&mut out)?;
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Parse a canonical envelope. Fail-closed on malformed/trailing input.
    pub fn parse(data: &[u8]) -> Result<Self, PrimitiveError> {
        let mut i = 0;
        let version = read_u8(data, &mut i)?;
        if version != ENVELOPE_VERSION {
            return Err(PrimitiveError::InvalidLength);
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
        let end = i
            .checked_add(payload_len)
            .ok_or(PrimitiveError::LimitExceeded)?;
        if end != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let payload = data[i..end].to_vec();

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
        env.validate_payload_metadata()?;
        Ok(env)
    }

    /// Canonical AEAD associated data.
    ///
    /// This binds every routing field, payload type, voice metadata, and the
    /// exact payload length while deliberately omitting the payload body because
    /// that body is the AEAD plaintext. Unlike the old clone-and-clear shortcut,
    /// SyntheticVoice metadata remains self-consistent and authenticated.
    pub fn associated_data(&self) -> Result<Vec<u8>, PrimitiveError> {
        self.validate_limits()?;
        self.validate_payload_metadata()?;
        let mut out = Vec::with_capacity(ENVELOPE_AD_DOMAIN.len() + 256);
        out.extend_from_slice(ENVELOPE_AD_DOMAIN);
        self.write_authenticated_metadata(&mut out)?;
        Ok(out)
    }

    fn write_authenticated_metadata(&self, out: &mut Vec<u8>) -> Result<(), PrimitiveError> {
        out.push(self.protocol_version);
        out.push(self.crypto_suite.as_u8());
        write_bytes_u16(out, &self.conversation_id)?;
        write_bytes_u16(out, &self.sender_user_id)?;
        write_bytes_u16(out, &self.sender_device_id)?;
        write_bytes_u16(out, &self.recipient_user_id)?;
        write_bytes_u16(out, &self.recipient_device_id)?;
        write_bytes_u16(out, &self.message_id)?;
        out.push(self.message_type);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.created_timestamp.to_le_bytes());
        out.push(self.payload_type.as_u8());

        if let Some(meta) = &self.synthetic_voice {
            write_bytes_u16(out, meta.codec.as_bytes())?;
            out.extend_from_slice(&meta.duration_ms.to_le_bytes());
            out.extend_from_slice(&meta.payload_length.to_le_bytes());
        }

        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        Ok(())
    }

    fn validate_payload_metadata(&self) -> Result<(), PrimitiveError> {
        match (self.payload_type, &self.synthetic_voice) {
            (PayloadType::SyntheticVoice, Some(meta)) => {
                if meta.codec.is_empty() || meta.codec.len() > MAX_ID_LEN || !meta.codec.is_ascii() {
                    return Err(PrimitiveError::InvalidLength);
                }
                if meta.payload_length as usize != self.payload.len() {
                    return Err(PrimitiveError::InvalidLength);
                }
            }
            (PayloadType::SyntheticVoice, None) => return Err(PrimitiveError::InvalidLength),
            (_, Some(_)) => return Err(PrimitiveError::InvalidLength),
            (_, None) => {}
        }
        Ok(())
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
        if self.payload.len() > MAX_PAYLOAD_LEN || self.payload.len() > u32::MAX as usize {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok(())
    }
}

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
    let end = i.checked_add(2).ok_or(PrimitiveError::LimitExceeded)?;
    if end > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let v = u16::from_le_bytes(data[*i..end].try_into().unwrap());
    *i = end;
    Ok(v)
}

fn read_u32(data: &[u8], i: &mut usize) -> Result<u32, PrimitiveError> {
    let end = i.checked_add(4).ok_or(PrimitiveError::LimitExceeded)?;
    if end > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let v = u32::from_le_bytes(data[*i..end].try_into().unwrap());
    *i = end;
    Ok(v)
}

fn read_u64(data: &[u8], i: &mut usize) -> Result<u64, PrimitiveError> {
    let end = i.checked_add(8).ok_or(PrimitiveError::LimitExceeded)?;
    if end > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let v = u64::from_le_bytes(data[*i..end].try_into().unwrap());
    *i = end;
    Ok(v)
}

fn read_bytes_u16(data: &[u8], i: &mut usize) -> Result<Vec<u8>, PrimitiveError> {
    let len = read_u16(data, i)? as usize;
    if len > MAX_ID_LEN {
        return Err(PrimitiveError::InvalidLength);
    }
    let end = i.checked_add(len).ok_or(PrimitiveError::LimitExceeded)?;
    if end > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let v = data[*i..end].to_vec();
    *i = end;
    Ok(v)
}

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

    fn voice_envelope() -> Envelope {
        Envelope {
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
        assert_ne!(
            env_a.associated_data().unwrap(),
            env_b.associated_data().unwrap()
        );
    }

    #[test]
    fn device_binding_prevents_move() {
        let mut env = sample_envelope();
        let ad1 = env.associated_data().unwrap();
        env.recipient_device_id = b"device-OTHER".to_vec();
        let ad2 = env.associated_data().unwrap();
        assert_ne!(ad1, ad2);
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut bytes = sample_envelope().canonical_bytes().unwrap();
        bytes[0] = 99;
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
        let env = voice_envelope();
        let bytes = env.canonical_bytes().unwrap();
        let parsed = Envelope::parse(&bytes).unwrap();
        assert_eq!(env, parsed);
    }

    #[test]
    fn synthetic_voice_associated_data_is_valid_and_binds_metadata() {
        let env = voice_envelope();
        let ad = env.associated_data().unwrap();
        assert!(!ad.is_empty());

        let mut changed_duration = env.clone();
        changed_duration.synthetic_voice.as_mut().unwrap().duration_ms += 1;
        assert_ne!(ad, changed_duration.associated_data().unwrap());

        // Payload contents are plaintext, not AD. Same-length payload content
        // therefore does not alter metadata AD; AEAD authenticates the body.
        let mut changed_body = env.clone();
        changed_body.payload = b"other".to_vec();
        assert_eq!(ad, changed_body.associated_data().unwrap());
    }

    #[test]
    fn synthetic_voice_length_mismatch_rejected_for_body_and_ad() {
        let mut env = voice_envelope();
        env.synthetic_voice.as_mut().unwrap().payload_length = 99;
        assert!(env.canonical_bytes().is_err());
        assert!(env.associated_data().is_err());
    }

    #[test]
    fn associated_data_stable_for_same_envelope() {
        let env = sample_envelope();
        assert_eq!(env.associated_data().unwrap(), env.associated_data().unwrap());
    }
}
