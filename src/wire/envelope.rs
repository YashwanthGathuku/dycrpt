//! VoiceChat Authenticated Envelope
//!
//! Versioned application message whose security-sensitive metadata is
//! cryptographically bound. Designed so that a ciphertext produced for
//! conversation A / device X cannot authenticate under conversation B /
//! device Y.
//!
//! Serialization is strictly canonical: fixed field order, explicit lengths,
//! no maps, no optional reordering, no duplicate fields.

use std::convert::TryInto;

use crate::primitives::error::PrimitiveError;

/// Current protocol version for the application envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolVersion {
    V1 = 1,
}

impl ProtocolVersion {
    pub fn from_u8(v: u8) -> Result<Self, EnvelopeError> {
        match v {
            1 => Ok(Self::V1),
            _ => Err(EnvelopeError::UnsupportedVersion(v)),
        }
    }
}

/// Cryptographic suite identifier (authenticated).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CryptoSuite {
    /// X25519 + ML-KEM-768 + HKDF-SHA256 + AES-256-GCM (Triple Ratchet path)
    PqxdhTripleAes256Gcm = 1,
}

impl CryptoSuite {
    pub fn from_u16(v: u16) -> Result<Self, EnvelopeError> {
        match v {
            1 => Ok(Self::PqxdhTripleAes256Gcm),
            _ => Err(EnvelopeError::UnsupportedSuite(v)),
        }
    }
}

/// High-level message type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Application = 1,
    Acknowledgement = 2,
    Edit = 3,
    Control = 4,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Result<Self, EnvelopeError> {
        match v {
            1 => Ok(Self::Application),
            2 => Ok(Self::Acknowledgement),
            3 => Ok(Self::Edit),
            4 => Ok(Self::Control),
            _ => Err(EnvelopeError::InvalidMessageType(v)),
        }
    }
}

/// Payload content type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    Text = 1,
    SyntheticVoice = 2,
    Edit = 3,
    Acknowledgement = 4,
    Binary = 5,
}

impl PayloadType {
    pub fn from_u8(v: u8) -> Result<Self, EnvelopeError> {
        match v {
            1 => Ok(Self::Text),
            2 => Ok(Self::SyntheticVoice),
            3 => Ok(Self::Edit),
            4 => Ok(Self::Acknowledgement),
            5 => Ok(Self::Binary),
            _ => Err(EnvelopeError::InvalidPayloadType(v)),
        }
    }
}

/// Maximum accepted payload size (prevents memory exhaustion).
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024; // 1 MiB

/// Maximum length for opaque identifier fields.
pub const MAX_ID_LEN: usize = 64;

/// Errors specific to envelope construction / parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    UnsupportedVersion(u8),
    UnsupportedSuite(u16),
    InvalidMessageType(u8),
    InvalidPayloadType(u8),
    DuplicateField,
    UnknownCriticalField,
    IntegerOverflow,
    OversizedPayload,
    OversizedId,
    InvalidUtf8,
    MalformedLength,
    InvalidFieldOrder,
    MissingRequiredField,
    SyntheticVoiceMetadataMissing,
    Other(String),
}

impl From<EnvelopeError> for PrimitiveError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::MalformedLength | EnvelopeError::OversizedPayload => {
                PrimitiveError::InvalidLength
            }
            _ => PrimitiveError::Internal,
        }
    }
}

/// Synthetic-voice specific metadata (bound when payload_type == SyntheticVoice).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticVoiceMeta {
    pub codec: String,       // e.g. "opus"
    pub duration_ms: u32,
    pub payload_length: u32, // cleartext length before any padding
}

/// The authenticated application envelope.
///
/// All fields below are either placed in AEAD associated data or inside the
/// encrypted payload so that they are cryptographically bound to the ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub protocol_version: ProtocolVersion,
    pub crypto_suite: CryptoSuite,
    pub conversation_id: Vec<u8>,
    pub sender_user_id: Vec<u8>,
    pub sender_device_id: Vec<u8>,
    pub recipient_user_id: Vec<u8>,
    pub recipient_device_id: Vec<u8>,
    pub message_id: Vec<u8>,
    pub message_type: MessageType,
    pub sequence: u64,
    pub created_timestamp: u64, // Unix milliseconds
    pub payload_type: PayloadType,
    pub synthetic_voice: Option<SyntheticVoiceMeta>,
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Build associated-data bytes that must be supplied to the ratchet AEAD.
    ///
    /// These fields are authenticated but not encrypted, so the transport may
    /// inspect them for routing while any modification or cross-context reuse
    /// causes authentication failure.
    pub fn associated_data(&self) -> Vec<u8> {
        // Canonical order, length-prefixed. This exact byte sequence is what
        // the AEAD authenticates.
        let mut ad = Vec::with_capacity(256);
        ad.push(self.protocol_version as u8);
        ad.extend_from_slice(&(self.crypto_suite as u16).to_le_bytes());
        write_bytes(&mut ad, &self.conversation_id);
        write_bytes(&mut ad, &self.sender_user_id);
        write_bytes(&mut ad, &self.sender_device_id);
        write_bytes(&mut ad, &self.recipient_user_id);
        write_bytes(&mut ad, &self.recipient_device_id);
        write_bytes(&mut ad, &self.message_id);
        ad.push(self.message_type as u8);
        ad.extend_from_slice(&self.sequence.to_le_bytes());
        ad.extend_from_slice(&self.created_timestamp.to_le_bytes());
        ad.push(self.payload_type as u8);
        if let Some(ref meta) = self.synthetic_voice {
            ad.push(1); // present
            write_str(&mut ad, &meta.codec);
            ad.extend_from_slice(&meta.duration_ms.to_le_bytes());
            ad.extend_from_slice(&meta.payload_length.to_le_bytes());
        } else {
            ad.push(0); // absent
        }
        ad
    }

    /// Canonical serialization of the *confidential* portion (the payload and
    /// any fields that must stay private). This becomes the plaintext fed to
    /// the Double Ratchet / Triple Ratchet encrypt.
    pub fn confidential_plaintext(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate()?;
        let mut out = Vec::with_capacity(64 + self.payload.len());
        // Version of the confidential blob (independent of protocol_version)
        out.push(1);
        out.push(self.payload_type as u8);
        if let Some(ref meta) = self.synthetic_voice {
            out.push(1);
            write_str(&mut out, &meta.codec)?;
            out.extend_from_slice(&meta.duration_ms.to_le_bytes());
            out.extend_from_slice(&meta.payload_length.to_le_bytes());
        } else {
            out.push(0);
        }
        write_bytes(&mut out, &self.payload);
        Ok(out)
    }

    /// Parse the confidential plaintext recovered after successful AEAD decrypt.
    pub fn from_confidential_plaintext(
        plaintext: &[u8],
        // Binding fields that were authenticated via AD and already verified
        // by the caller against the expected conversation / devices.
        binding: BindingFields,
    ) -> Result<Self, EnvelopeError> {
        let mut i = 0;
        let version = read_u8(plaintext, &mut i)?;
        if version != 1 {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }
        let payload_type = PayloadType::from_u8(read_u8(plaintext, &mut i)?)?;
        let has_sv = read_u8(plaintext, &mut i)?;
        let synthetic_voice = if has_sv == 1 {
            let codec = read_str(plaintext, &mut i)?;
            let duration_ms = read_u32(plaintext, &mut i)?;
            let payload_length = read_u32(plaintext, &mut i)?;
            Some(SyntheticVoiceMeta {
                codec,
                duration_ms,
                payload_length,
            })
        } else if has_sv == 0 {
            None
        } else {
            return Err(EnvelopeError::MalformedLength);
        };
        let payload = read_bytes(plaintext, &mut i)?;
        if i != plaintext.len() {
            return Err(EnvelopeError::MalformedLength); // trailing data
        }
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(EnvelopeError::OversizedPayload);
        }
        if payload_type == PayloadType::SyntheticVoice && synthetic_voice.is_none() {
            return Err(EnvelopeError::SyntheticVoiceMetadataMissing);
        }

        let env = Self {
            protocol_version: binding.protocol_version,
            crypto_suite: binding.crypto_suite,
            conversation_id: binding.conversation_id,
            sender_user_id: binding.sender_user_id,
            sender_device_id: binding.sender_device_id,
            recipient_user_id: binding.recipient_user_id,
            recipient_device_id: binding.recipient_device_id,
            message_id: binding.message_id,
            message_type: binding.message_type,
            sequence: binding.sequence,
            created_timestamp: binding.created_timestamp,
            payload_type,
            synthetic_voice,
            payload,
        };
        env.validate()?;
        Ok(env)
    }

    /// Structural validation before encryption or after decryption.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.conversation_id.is_empty() || self.conversation_id.len() > MAX_ID_LEN {
            return Err(EnvelopeError::OversizedId);
        }
        for id in [
            &self.sender_user_id,
            &self.sender_device_id,
            &self.recipient_user_id,
            &self.recipient_device_id,
            &self.message_id,
        ] {
            if id.is_empty() || id.len() > MAX_ID_LEN {
                return Err(EnvelopeError::OversizedId);
            }
        }
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(EnvelopeError::OversizedPayload);
        }
        if self.payload_type == PayloadType::SyntheticVoice {
            match &self.synthetic_voice {
                None => return Err(EnvelopeError::SyntheticVoiceMetadataMissing),
                Some(m) => {
                    if m.codec.is_empty() || m.codec.len() > 32 {
                        return Err(EnvelopeError::InvalidUtf8);
                    }
                    if !m.codec.is_ascii() {
                        return Err(EnvelopeError::InvalidUtf8);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Binding fields that were carried in AD and have already been authenticated
/// by the AEAD. Supplied when reconstructing the Envelope after decrypt.
#[derive(Clone, Debug)]
pub struct BindingFields {
    pub protocol_version: ProtocolVersion,
    pub crypto_suite: CryptoSuite,
    pub conversation_id: Vec<u8>,
    pub sender_user_id: Vec<u8>,
    pub sender_device_id: Vec<u8>,
    pub recipient_user_id: Vec<u8>,
    pub recipient_device_id: Vec<u8>,
    pub message_id: Vec<u8>,
    pub message_type: MessageType,
    pub sequence: u64,
    pub created_timestamp: u64,
}

// ---------------------------------------------------------------------------
// Canonical serialization helpers (strict, length-prefixed, fixed order)
// ---------------------------------------------------------------------------

fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
}

fn write_str(buf: &mut Vec<u8>, s: &str) -> Result<(), EnvelopeError> {
    if !s.is_ascii() {
        return Err(EnvelopeError::InvalidUtf8);
    }
    write_bytes(buf, s.as_bytes());
    Ok(())
}

fn read_u8(data: &[u8], i: &mut usize) -> Result<u8, EnvelopeError> {
    if *i >= data.len() {
        return Err(EnvelopeError::MalformedLength);
    }
    let v = data[*i];
    *i += 1;
    Ok(v)
}

fn read_u32(data: &[u8], i: &mut usize) -> Result<u32, EnvelopeError> {
    if *i + 4 > data.len() {
        return Err(EnvelopeError::MalformedLength);
    }
    let v = u32::from_le_bytes(data[*i..*i + 4].try_into().unwrap());
    *i += 4;
    Ok(v)
}

fn read_bytes(data: &[u8], i: &mut usize) -> Result<Vec<u8>, EnvelopeError> {
    let len = read_u32(data, i)? as usize;
    if len > MAX_PAYLOAD_LEN {
        return Err(EnvelopeError::OversizedPayload);
    }
    if *i + len > data.len() {
        return Err(EnvelopeError::MalformedLength);
    }
    let v = data[*i..*i + len].to_vec();
    *i += len;
    Ok(v)
}

fn read_str(data: &[u8], i: &mut usize) -> Result<String, EnvelopeError> {
    let bytes = read_bytes(data, i)?;
    if bytes.len() > 32 {
        return Err(EnvelopeError::OversizedId);
    }
    let s = std::str::from_utf8(&bytes).map_err(|_| EnvelopeError::InvalidUtf8)?;
    if !s.is_ascii() {
        return Err(EnvelopeError::InvalidUtf8);
    }
    Ok(s.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> Envelope {
        Envelope {
            protocol_version: ProtocolVersion::V1,
            crypto_suite: CryptoSuite::PqxdhTripleAes256Gcm,
            conversation_id: b"conv-abc".to_vec(),
            sender_user_id: b"user-alice".to_vec(),
            sender_device_id: b"dev-1".to_vec(),
            recipient_user_id: b"user-bob".to_vec(),
            recipient_device_id: b"dev-9".to_vec(),
            message_id: b"msg-001".to_vec(),
            message_type: MessageType::Application,
            sequence: 42,
            created_timestamp: 1_700_000_000_000,
            payload_type: PayloadType::Text,
            synthetic_voice: None,
            payload: b"hello voicechat".to_vec(),
        }
    }

    #[test]
    fn associated_data_is_deterministic() {
        let e = sample_envelope();
        let ad1 = e.associated_data();
        let ad2 = e.associated_data();
        assert_eq!(ad1, ad2);
        // Conversation id appears in the AD
        assert!(ad1.windows(8).any(|w| w == b"conv-abc"));
    }

    #[test]
    fn confidential_roundtrip() {
        let e = sample_envelope();
        let pt = e.confidential_plaintext().unwrap();
        let binding = BindingFields {
            protocol_version: e.protocol_version,
            crypto_suite: e.crypto_suite,
            conversation_id: e.conversation_id.clone(),
            sender_user_id: e.sender_user_id.clone(),
            sender_device_id: e.sender_device_id.clone(),
            recipient_user_id: e.recipient_user_id.clone(),
            recipient_device_id: e.recipient_device_id.clone(),
            message_id: e.message_id.clone(),
            message_type: e.message_type,
            sequence: e.sequence,
            created_timestamp: e.created_timestamp,
        };
        let recovered = Envelope::from_confidential_plaintext(&pt, binding).unwrap();
        assert_eq!(recovered.payload, e.payload);
        assert_eq!(recovered.payload_type, e.payload_type);
    }

    #[test]
    fn cross_conversation_ad_differs() {
        let mut e1 = sample_envelope();
        let mut e2 = sample_envelope();
        e2.conversation_id = b"conv-OTHER".to_vec();
        assert_ne!(e1.associated_data(), e2.associated_data());
    }

    #[test]
    fn cross_device_ad_differs() {
        let e1 = sample_envelope();
        let mut e2 = sample_envelope();
        e2.recipient_device_id = b"dev-OTHER".to_vec();
        assert_ne!(e1.associated_data(), e2.associated_data());
    }

    #[test]
    fn oversized_payload_rejected() {
        let mut e = sample_envelope();
        e.payload = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert!(matches!(e.validate(), Err(EnvelopeError::OversizedPayload)));
    }

    #[test]
    fn synthetic_voice_requires_metadata() {
        let mut e = sample_envelope();
        e.payload_type = PayloadType::SyntheticVoice;
        e.synthetic_voice = None;
        assert!(matches!(
            e.validate(),
            Err(EnvelopeError::SyntheticVoiceMetadataMissing)
        ));
    }

    #[test]
    fn synthetic_voice_metadata_bound() {
        let mut e = sample_envelope();
        e.payload_type = PayloadType::SyntheticVoice;
        e.synthetic_voice = Some(SyntheticVoiceMeta {
            codec: "opus".into(),
            duration_ms: 1500,
            payload_length: 3200,
        });
        e.payload = vec![0u8; 100];
        let ad = e.associated_data();
        // codec string appears
        assert!(ad.windows(4).any(|w| w == b"opus"));
        e.validate().unwrap();
    }

    #[test]
    fn empty_conversation_id_rejected() {
        let mut e = sample_envelope();
        e.conversation_id.clear();
        assert!(matches!(e.validate(), Err(EnvelopeError::OversizedId)));
    }

    #[test]
    fn trailing_data_in_plaintext_rejected() {
        let e = sample_envelope();
        let mut pt = e.confidential_plaintext().unwrap();
        pt.push(0xff); // trailing
        let binding = BindingFields {
            protocol_version: e.protocol_version,
            crypto_suite: e.crypto_suite,
            conversation_id: e.conversation_id.clone(),
            sender_user_id: e.sender_user_id.clone(),
            sender_device_id: e.sender_device_id.clone(),
            recipient_user_id: e.recipient_user_id.clone(),
            recipient_device_id: e.recipient_device_id.clone(),
            message_id: e.message_id.clone(),
            message_type: e.message_type,
            sequence: e.sequence,
            created_timestamp: e.created_timestamp,
        };
        assert!(matches!(
            Envelope::from_confidential_plaintext(&pt, binding),
            Err(EnvelopeError::MalformedLength)
        ));
    }
}
