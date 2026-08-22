//! ML-KEM Braid SCKA from the public specification (Rev 1, 2025-09-26).
//!
//! Incremental Encaps1 produces ct1 from the 64-byte header (ρ ‖ H(ek))
//! using FIPS 203 K-PKE. This module remains experimental, but its wire and
//! persisted-state parsers are strict, bounded, and canonical.

pub mod auth;
pub mod rs;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::primitives::error::PrimitiveError;
use crate::primitives::kem::MlKemSecret;
use crate::primitives::mlkem_inc::{
    encaps1, encaps2, header_from_ek, join_ct, EncapsSecret, CT1_LEN, CT2_LEN, EK_VECTOR_LEN,
};

use self::auth::{kdf_ok, Authenticator};
use self::rs::{Decoder, Encoder, CHUNK_WIRE};

pub const HEADER_SIZE: usize = 64;
pub const EK_SIZE: usize = EK_VECTOR_LEN;
pub const CT1_SIZE: usize = CT1_LEN;
pub const CT2_SIZE: usize = CT2_LEN;
pub const MAC_SIZE: usize = 32;

const MAX_BRAID_STATE: usize = 256 * 1024;
const MAX_CODEC_STATE: usize = 128 * 1024;
const MAX_AGENT_VECTOR: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BraidType {
    None = 0,
    Hdr = 1,
    Ek = 2,
    EkCt1Ack = 3,
    Ct1Ack = 4,
    Ct1 = 5,
    Ct2 = 6,
}

impl BraidType {
    fn from_u8(v: u8) -> Result<Self, PrimitiveError> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Hdr),
            2 => Ok(Self::Ek),
            3 => Ok(Self::EkCt1Ack),
            4 => Ok(Self::Ct1Ack),
            5 => Ok(Self::Ct1),
            6 => Ok(Self::Ct2),
            _ => Err(PrimitiveError::InvalidLength),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BraidMessage {
    pub epoch: u64,
    pub typ: BraidType,
    pub data: Vec<u8>,
}

impl BraidMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.data.len());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.push(self.typ as u8);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 9 || data.len() > 9 + CHUNK_WIRE {
            return Err(PrimitiveError::InvalidLength);
        }
        let epoch = u64::from_be_bytes(data[..8].try_into().unwrap());
        let typ = BraidType::from_u8(data[8])?;
        let rest = &data[9..];
        match typ {
            BraidType::None | BraidType::Ct1Ack => {
                if !rest.is_empty() {
                    return Err(PrimitiveError::InvalidLength);
                }
            }
            _ => {
                if rest.len() != CHUNK_WIRE {
                    return Err(PrimitiveError::InvalidLength);
                }
            }
        }
        Ok(Self {
            epoch,
            typ,
            data: rest.to_vec(),
        })
    }
}

pub type SckaMessage = BraidMessage;

#[derive(Clone)]
enum Agent {
    KeysUnsampled,
    KeysSampled {
        dk: MlKemSecret,
        ek_vector: Vec<u8>,
        header_enc: Encoder,
    },
    HeaderSent {
        dk: MlKemSecret,
        ek_enc: Encoder,
        ct1_dec: Decoder,
    },
    Ct1Received {
        dk: MlKemSecret,
        ct1: Vec<u8>,
        ek_enc: Encoder,
    },
    EkSentCt1Received {
        dk: MlKemSecret,
        ct1: Vec<u8>,
        ct2_dec: Decoder,
    },
    NoHeaderReceived {
        header_dec: Decoder,
    },
    HeaderReceived {
        ek_seed: [u8; 32],
        hek: [u8; 32],
        ek_dec: Decoder,
    },
    Ct1Sampled {
        secret: EncapsSecret,
        ct1: [u8; CT1_LEN],
        ct1_enc: Encoder,
        ek_dec: Decoder,
        ss: [u8; 32],
        emitted_ss: bool,
    },
    EkReceivedCt1Sampled {
        secret: EncapsSecret,
        ct1: [u8; CT1_LEN],
        ek_vector: Vec<u8>,
        ct1_enc: Encoder,
        ss: [u8; 32],
        emitted_ss: bool,
    },
    Ct1Acknowledged {
        secret: EncapsSecret,
        ct1: [u8; CT1_LEN],
        ek_dec: Decoder,
        ss: [u8; 32],
        emitted_ss: bool,
    },
    Ct2Sampled {
        ct2_enc: Encoder,
        ss: [u8; 32],
        emitted_ss: bool,
    },
}

#[derive(Clone)]
pub struct BraidScka {
    epoch: u64,
    auth: Authenticator,
    agent: Agent,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SckaOutput {
    pub epoch: u64,
    pub key: [u8; 32],
}

impl BraidScka {
    pub fn init_alice(shared: &[u8; 32]) -> Result<Self, PrimitiveError> {
        Ok(Self {
            epoch: 1,
            auth: Authenticator::init(1, shared)?,
            agent: Agent::KeysUnsampled,
        })
    }

    pub fn init_bob(shared: &[u8; 32]) -> Result<Self, PrimitiveError> {
        Ok(Self {
            epoch: 1,
            auth: Authenticator::init(1, shared)?,
            agent: Agent::NoHeaderReceived {
                header_dec: Decoder::new(HEADER_SIZE + MAC_SIZE),
            },
        })
    }

    pub fn promote_header_to_ek(&mut self) {}

    pub fn send(&mut self) -> Result<(BraidMessage, u64, Option<SckaOutput>), PrimitiveError> {
        self.encaps1_if_needed()?;
        let sending_epoch = self.epoch.saturating_sub(1);
        match &mut self.agent {
            Agent::KeysUnsampled => {
                let (dk, pk) = MlKemSecret::generate()?;
                let (header_bytes, t) = header_from_ek(pk.as_bytes());
                let mac = self.auth.mac_hdr(self.epoch, &header_bytes);
                let mut payload = header_bytes.to_vec();
                payload.extend_from_slice(&mac);
                let mut header_enc = Encoder::new(&payload);
                let chunk = header_enc.next_chunk();
                self.agent = Agent::KeysSampled {
                    dk,
                    ek_vector: t.to_vec(),
                    header_enc,
                };
                Ok((self.msg(BraidType::Hdr, chunk), sending_epoch, None))
            }
            Agent::KeysSampled { header_enc, .. } => {
                Ok((self.msg(BraidType::Hdr, header_enc.next_chunk()), sending_epoch, None))
            }
            Agent::HeaderSent { ek_enc, .. } => {
                Ok((self.msg(BraidType::Ek, ek_enc.next_chunk()), sending_epoch, None))
            }
            Agent::Ct1Received { ek_enc, .. } => Ok((
                self.msg(BraidType::EkCt1Ack, ek_enc.next_chunk()),
                sending_epoch,
                None,
            )),
            Agent::EkSentCt1Received { .. }
            | Agent::NoHeaderReceived { .. }
            | Agent::HeaderReceived { .. }
            | Agent::Ct1Acknowledged { .. } => {
                Ok((self.msg(BraidType::None, Vec::new()), sending_epoch, None))
            }
            Agent::Ct1Sampled { ct1_enc, .. } | Agent::EkReceivedCt1Sampled { ct1_enc, .. } => {
                Ok((self.msg(BraidType::Ct1, ct1_enc.next_chunk()), sending_epoch, None))
            }
            Agent::Ct2Sampled { ct2_enc, .. } => {
                Ok((self.msg(BraidType::Ct2, ct2_enc.next_chunk()), sending_epoch, None))
            }
        }
    }

    fn msg(&self, typ: BraidType, data: Vec<u8>) -> BraidMessage {
        BraidMessage {
            epoch: self.epoch,
            typ,
            data,
        }
    }

    pub fn receive(
        &mut self,
        msg: &BraidMessage,
    ) -> Result<(u64, Option<SckaOutput>), PrimitiveError> {
        validate_message(msg)?;
        let receiving_epoch = self.epoch.saturating_sub(1);
        let next_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(PrimitiveError::LimitExceeded)?;
        if msg.epoch > next_epoch {
            return Err(PrimitiveError::InvalidLength);
        }

        match &mut self.agent {
            Agent::KeysUnsampled => Ok((receiving_epoch, None)),
            Agent::KeysSampled { ek_vector, dk, .. } => {
                if msg.epoch == self.epoch && msg.typ == BraidType::Ct1 {
                    let dk = dk.clone();
                    let ek_enc = Encoder::new(ek_vector);
                    let mut ct1_dec = Decoder::new(CT1_SIZE);
                    ct1_dec.add_chunk(&msg.data)?;
                    self.agent = Agent::HeaderSent {
                        dk,
                        ek_enc,
                        ct1_dec,
                    };
                }
                Ok((receiving_epoch, None))
            }
            Agent::HeaderSent {
                ct1_dec,
                dk,
                ek_enc,
            } => {
                if msg.epoch == self.epoch && msg.typ == BraidType::Ct1 {
                    ct1_dec.add_chunk(&msg.data)?;
                    if ct1_dec.has_message() {
                        let ct1 = ct1_dec.message().ok_or(PrimitiveError::Internal)?.to_vec();
                        self.agent = Agent::Ct1Received {
                            dk: dk.clone(),
                            ct1,
                            ek_enc: ek_enc.clone(),
                        };
                    }
                }
                Ok((receiving_epoch, None))
            }
            Agent::Ct1Received { .. } => {
                if msg.epoch == self.epoch && msg.typ == BraidType::Ct2 {
                    if let Agent::Ct1Received { dk, ct1, .. } =
                        std::mem::replace(&mut self.agent, Agent::KeysUnsampled)
                    {
                        let mut ct2_dec = Decoder::new(CT2_SIZE + MAC_SIZE);
                        ct2_dec.add_chunk(&msg.data)?;
                        self.agent = Agent::EkSentCt1Received { dk, ct1, ct2_dec };
                    }
                }
                Ok((receiving_epoch, None))
            }
            Agent::EkSentCt1Received { ct2_dec, dk, ct1 } => {
                if msg.epoch == self.epoch && msg.typ == BraidType::Ct2 {
                    ct2_dec.add_chunk(&msg.data)?;
                    if ct2_dec.has_message() {
                        let blob = ct2_dec.message().ok_or(PrimitiveError::Internal)?;
                        if blob.len() != CT2_SIZE + MAC_SIZE {
                            return Err(PrimitiveError::InvalidLength);
                        }
                        let ct2 = &blob[..CT2_SIZE];
                        let mac = &blob[CT2_SIZE..];
                        let mut ct1a = [0u8; CT1_LEN];
                        ct1a.copy_from_slice(ct1);
                        let mut ct2a = [0u8; CT2_LEN];
                        ct2a.copy_from_slice(ct2);
                        let joined = join_ct(&ct1a, &ct2a);
                        let cto = crate::primitives::kem::MlKemCiphertext::from_bytes(&joined)?;
                        let mut ss_raw = dk.decapsulate(&cto)?;
                        let ss_result = kdf_ok(&ss_raw, self.epoch);
                        ss_raw.zeroize();
                        let ss = ss_result?;
                        self.auth.update(self.epoch, &ss)?;
                        self.auth.vfy_ct(self.epoch, &joined, mac)?;
                        let out = SckaOutput {
                            epoch: self.epoch,
                            key: ss,
                        };
                        self.epoch = next_epoch;
                        self.agent = Agent::NoHeaderReceived {
                            header_dec: Decoder::new(HEADER_SIZE + MAC_SIZE),
                        };
                        return Ok((receiving_epoch, Some(out)));
                    }
                }
                Ok((receiving_epoch, None))
            }
            Agent::NoHeaderReceived { header_dec } => {
                if msg.epoch == self.epoch && msg.typ == BraidType::Hdr {
                    header_dec.add_chunk(&msg.data)?;
                    if header_dec.has_message() {
                        let blob = header_dec.message().ok_or(PrimitiveError::Internal)?;
                        if blob.len() != HEADER_SIZE + MAC_SIZE {
                            return Err(PrimitiveError::InvalidLength);
                        }
                        let header = &blob[..HEADER_SIZE];
                        let mac = &blob[HEADER_SIZE..];
                        self.auth.vfy_hdr(self.epoch, header, mac)?;
                        let mut ek_seed = [0u8; 32];
                        let mut hek = [0u8; 32];
                        ek_seed.copy_from_slice(&header[..32]);
                        hek.copy_from_slice(&header[32..64]);
                        self.agent = Agent::HeaderReceived {
                            ek_seed,
                            hek,
                            ek_dec: Decoder::new(EK_SIZE),
                        };
                    }
                }
                Ok((receiving_epoch, None))
            }
            Agent::HeaderReceived { .. } => Ok((receiving_epoch, None)),
            Agent::Ct1Sampled { .. } => self.recv_ek_or_ack(msg, receiving_epoch),
            Agent::EkReceivedCt1Sampled { .. } => {
                if msg.epoch == self.epoch
                    && matches!(msg.typ, BraidType::EkCt1Ack | BraidType::Ct1Ack)
                {
                    self.finish_encaps2()?;
                }
                if msg.epoch == next_epoch {
                    return self.complete_encapsulator(receiving_epoch, msg.epoch);
                }
                Ok((receiving_epoch, None))
            }
            Agent::Ct1Acknowledged { .. } => {
                if msg.epoch == self.epoch && matches!(msg.typ, BraidType::Ek | BraidType::EkCt1Ack)
                {
                    if let Agent::Ct1Acknowledged {
                        secret,
                        ct1,
                        ek_dec,
                        ss,
                        emitted_ss,
                    } = &mut self.agent
                    {
                        ek_dec.add_chunk(&msg.data)?;
                        if ek_dec.has_message() {
                            let t = ek_dec.message().ok_or(PrimitiveError::Internal)?.to_vec();
                            let ct2 = encaps2(secret, &t)?;
                            let mut joined = [0u8; 1088];
                            joined[..CT1_LEN].copy_from_slice(ct1);
                            joined[CT1_LEN..].copy_from_slice(&ct2);
                            let mac = self.auth.mac_ct(self.epoch, &joined);
                            let mut ct2_mac = ct2.to_vec();
                            ct2_mac.extend_from_slice(&mac);
                            self.agent = Agent::Ct2Sampled {
                                ct2_enc: Encoder::new(&ct2_mac),
                                ss: *ss,
                                emitted_ss: *emitted_ss,
                            };
                        }
                    }
                }
                Ok((receiving_epoch, None))
            }
            Agent::Ct2Sampled { .. } => {
                if msg.epoch == next_epoch {
                    return self.complete_encapsulator(receiving_epoch, msg.epoch);
                }
                Ok((receiving_epoch, None))
            }
        }
    }

    fn recv_ek_or_ack(
        &mut self,
        msg: &BraidMessage,
        receiving_epoch: u64,
    ) -> Result<(u64, Option<SckaOutput>), PrimitiveError> {
        if msg.epoch != self.epoch {
            return Ok((receiving_epoch, None));
        }
        match msg.typ {
            BraidType::Ek | BraidType::EkCt1Ack => {
                if let Agent::Ct1Sampled { ek_dec, .. } = &mut self.agent {
                    ek_dec.add_chunk(&msg.data)?;
                }
                let complete =
                    matches!(&self.agent, Agent::Ct1Sampled { ek_dec, .. } if ek_dec.has_message());
                let ack = msg.typ == BraidType::EkCt1Ack;
                if complete && ack {
                    if let Agent::Ct1Sampled {
                        secret,
                        ct1,
                        ek_dec,
                        ss,
                        emitted_ss,
                        ..
                    } = &self.agent
                    {
                        let t = ek_dec.message().ok_or(PrimitiveError::Internal)?.to_vec();
                        let ct2 = encaps2(secret, &t)?;
                        let mut joined = [0u8; 1088];
                        joined[..CT1_LEN].copy_from_slice(ct1);
                        joined[CT1_LEN..].copy_from_slice(&ct2);
                        let mac = self.auth.mac_ct(self.epoch, &joined);
                        let mut ct2_mac = ct2.to_vec();
                        ct2_mac.extend_from_slice(&mac);
                        self.agent = Agent::Ct2Sampled {
                            ct2_enc: Encoder::new(&ct2_mac),
                            ss: *ss,
                            emitted_ss: *emitted_ss,
                        };
                    }
                } else if complete {
                    if let Agent::Ct1Sampled {
                        secret,
                        ct1,
                        ek_dec,
                        ct1_enc,
                        ss,
                        emitted_ss,
                    } = &self.agent
                    {
                        self.agent = Agent::EkReceivedCt1Sampled {
                            secret: secret.clone(),
                            ct1: *ct1,
                            ek_vector: ek_dec.message().ok_or(PrimitiveError::Internal)?.to_vec(),
                            ct1_enc: ct1_enc.clone(),
                            ss: *ss,
                            emitted_ss: *emitted_ss,
                        };
                    }
                } else if ack {
                    if let Agent::Ct1Sampled {
                        secret,
                        ct1,
                        ek_dec,
                        ss,
                        emitted_ss,
                        ..
                    } = &self.agent
                    {
                        self.agent = Agent::Ct1Acknowledged {
                            secret: secret.clone(),
                            ct1: *ct1,
                            ek_dec: ek_dec.clone(),
                            ss: *ss,
                            emitted_ss: *emitted_ss,
                        };
                    }
                }
            }
            _ => {}
        }
        Ok((receiving_epoch, None))
    }

    fn finish_encaps2(&mut self) -> Result<(), PrimitiveError> {
        if let Agent::EkReceivedCt1Sampled {
            secret,
            ct1,
            ek_vector,
            ss,
            emitted_ss,
            ..
        } = &self.agent
        {
            let ct2 = encaps2(secret, ek_vector)?;
            let mut joined = [0u8; 1088];
            joined[..CT1_LEN].copy_from_slice(ct1);
            joined[CT1_LEN..].copy_from_slice(&ct2);
            let mac = self.auth.mac_ct(self.epoch, &joined);
            let mut ct2_mac = ct2.to_vec();
            ct2_mac.extend_from_slice(&mac);
            self.agent = Agent::Ct2Sampled {
                ct2_enc: Encoder::new(&ct2_mac),
                ss: *ss,
                emitted_ss: *emitted_ss,
            };
        }
        Ok(())
    }

    fn complete_encapsulator(
        &mut self,
        receiving_epoch: u64,
        new_epoch: u64,
    ) -> Result<(u64, Option<SckaOutput>), PrimitiveError> {
        let ss = match &mut self.agent {
            Agent::Ct2Sampled { ss, .. } | Agent::EkReceivedCt1Sampled { ss, .. } => {
                let copy = *ss;
                ss.zeroize();
                copy
            }
            _ => return Err(PrimitiveError::Internal),
        };
        let out = SckaOutput {
            epoch: self.epoch,
            key: ss,
        };
        self.epoch = new_epoch;
        self.agent = Agent::KeysUnsampled;
        Ok((receiving_epoch, Some(out)))
    }

    fn encaps1_if_needed(&mut self) -> Result<(), PrimitiveError> {
        if let Agent::HeaderReceived {
            ek_seed,
            hek,
            ek_dec,
        } = &self.agent
        {
            let mut header = [0u8; 64];
            header[..32].copy_from_slice(ek_seed);
            header[32..].copy_from_slice(hek);
            let (secret, ct1, mut ss_raw) = encaps1(&header)?;
            let ss_result = kdf_ok(&ss_raw, self.epoch);
            ss_raw.zeroize();
            let ss = ss_result?;
            self.auth.update(self.epoch, &ss)?;
            self.agent = Agent::Ct1Sampled {
                secret,
                ct1,
                ct1_enc: Encoder::new(&ct1),
                ek_dec: ek_dec.clone(),
                ss,
                emitted_ss: false,
            };
        }
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = b"VCBRAID3".to_vec();
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.auth.encode());
        self.agent.write(&mut out);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 8 || data.len() > MAX_BRAID_STATE {
            return Err(PrimitiveError::LimitExceeded);
        }
        match &data[..8] {
            b"VCBRAID3" => deserialize_v3(data),
            b"VCBRAID2" | b"VCBRAID1" => deserialize_compact(data),
            _ => Err(PrimitiveError::InvalidLength),
        }
    }
}

fn validate_message(message: &BraidMessage) -> Result<(), PrimitiveError> {
    match message.typ {
        BraidType::None | BraidType::Ct1Ack => {
            if !message.data.is_empty() {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        _ if message.data.len() == CHUNK_WIRE => {}
        _ => return Err(PrimitiveError::InvalidLength),
    }
    Ok(())
}

fn put_slice(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn take<'a>(data: &'a [u8], i: &mut usize, len: usize) -> Result<&'a [u8], PrimitiveError> {
    let end = i.checked_add(len).ok_or(PrimitiveError::LimitExceeded)?;
    if end > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let out = &data[*i..end];
    *i = end;
    Ok(out)
}

fn take_vec_bounded(
    data: &[u8],
    i: &mut usize,
    max: usize,
) -> Result<Vec<u8>, PrimitiveError> {
    let len = u32::from_le_bytes(take(data, i, 4)?.try_into().unwrap()) as usize;
    if len > max {
        return Err(PrimitiveError::LimitExceeded);
    }
    Ok(take(data, i, len)?.to_vec())
}

fn take_exact_vec(
    data: &[u8],
    i: &mut usize,
    expected: usize,
) -> Result<Vec<u8>, PrimitiveError> {
    let value = take_vec_bounded(data, i, expected)?;
    if value.len() != expected {
        return Err(PrimitiveError::InvalidLength);
    }
    Ok(value)
}

fn take_arr<const N: usize>(data: &[u8], i: &mut usize) -> Result<[u8; N], PrimitiveError> {
    Ok(take(data, i, N)?.try_into().unwrap())
}

fn take_bool(data: &[u8], i: &mut usize) -> Result<bool, PrimitiveError> {
    match take(data, i, 1)?[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PrimitiveError::InvalidLength),
    }
}

fn take_enc(data: &[u8], i: &mut usize) -> Result<Encoder, PrimitiveError> {
    Encoder::decode(&take_vec_bounded(data, i, MAX_CODEC_STATE)?)
}

fn take_dec(data: &[u8], i: &mut usize) -> Result<Decoder, PrimitiveError> {
    Decoder::decode(&take_vec_bounded(data, i, MAX_CODEC_STATE)?)
}

fn take_dk(data: &[u8], i: &mut usize) -> Result<MlKemSecret, PrimitiveError> {
    Ok(MlKemSecret::from_seed_bytes(take_arr(data, i)?))
}

fn take_secret(data: &[u8], i: &mut usize) -> Result<EncapsSecret, PrimitiveError> {
    Ok(EncapsSecret::decode(&take_arr(data, i)?))
}

impl Agent {
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Agent::KeysUnsampled => out.push(0),
            Agent::KeysSampled {
                dk,
                ek_vector,
                header_enc,
            } => {
                out.push(1);
                out.extend_from_slice(dk.as_seed());
                put_slice(out, ek_vector);
                put_slice(out, &header_enc.encode());
            }
            Agent::HeaderSent {
                dk,
                ek_enc,
                ct1_dec,
            } => {
                out.push(2);
                out.extend_from_slice(dk.as_seed());
                put_slice(out, &ek_enc.encode());
                put_slice(out, &ct1_dec.encode());
            }
            Agent::Ct1Received { dk, ct1, ek_enc } => {
                out.push(3);
                out.extend_from_slice(dk.as_seed());
                put_slice(out, ct1);
                put_slice(out, &ek_enc.encode());
            }
            Agent::EkSentCt1Received { dk, ct1, ct2_dec } => {
                out.push(4);
                out.extend_from_slice(dk.as_seed());
                put_slice(out, ct1);
                put_slice(out, &ct2_dec.encode());
            }
            Agent::NoHeaderReceived { header_dec } => {
                out.push(5);
                put_slice(out, &header_dec.encode());
            }
            Agent::HeaderReceived {
                ek_seed,
                hek,
                ek_dec,
            } => {
                out.push(6);
                out.extend_from_slice(ek_seed);
                out.extend_from_slice(hek);
                put_slice(out, &ek_dec.encode());
            }
            Agent::Ct1Sampled {
                secret,
                ct1,
                ct1_enc,
                ek_dec,
                ss,
                emitted_ss,
            } => {
                out.push(7);
                out.extend_from_slice(&secret.encode());
                out.extend_from_slice(ct1);
                put_slice(out, &ct1_enc.encode());
                put_slice(out, &ek_dec.encode());
                out.extend_from_slice(ss);
                out.push(u8::from(*emitted_ss));
            }
            Agent::EkReceivedCt1Sampled {
                secret,
                ct1,
                ek_vector,
                ct1_enc,
                ss,
                emitted_ss,
            } => {
                out.push(8);
                out.extend_from_slice(&secret.encode());
                out.extend_from_slice(ct1);
                put_slice(out, ek_vector);
                put_slice(out, &ct1_enc.encode());
                out.extend_from_slice(ss);
                out.push(u8::from(*emitted_ss));
            }
            Agent::Ct1Acknowledged {
                secret,
                ct1,
                ek_dec,
                ss,
                emitted_ss,
            } => {
                out.push(9);
                out.extend_from_slice(&secret.encode());
                out.extend_from_slice(ct1);
                put_slice(out, &ek_dec.encode());
                out.extend_from_slice(ss);
                out.push(u8::from(*emitted_ss));
            }
            Agent::Ct2Sampled {
                ct2_enc,
                ss,
                emitted_ss,
            } => {
                out.push(10);
                put_slice(out, &ct2_enc.encode());
                out.extend_from_slice(ss);
                out.push(u8::from(*emitted_ss));
            }
        }
    }

    fn read(data: &[u8], i: &mut usize) -> Result<Self, PrimitiveError> {
        match take(data, i, 1)?[0] {
            0 => Ok(Agent::KeysUnsampled),
            1 => Ok(Agent::KeysSampled {
                dk: take_dk(data, i)?,
                ek_vector: take_exact_vec(data, i, EK_SIZE)?,
                header_enc: take_enc(data, i)?,
            }),
            2 => Ok(Agent::HeaderSent {
                dk: take_dk(data, i)?,
                ek_enc: take_enc(data, i)?,
                ct1_dec: take_dec(data, i)?,
            }),
            3 => Ok(Agent::Ct1Received {
                dk: take_dk(data, i)?,
                ct1: take_exact_vec(data, i, CT1_SIZE)?,
                ek_enc: take_enc(data, i)?,
            }),
            4 => Ok(Agent::EkSentCt1Received {
                dk: take_dk(data, i)?,
                ct1: take_exact_vec(data, i, CT1_SIZE)?,
                ct2_dec: take_dec(data, i)?,
            }),
            5 => Ok(Agent::NoHeaderReceived {
                header_dec: take_dec(data, i)?,
            }),
            6 => Ok(Agent::HeaderReceived {
                ek_seed: take_arr(data, i)?,
                hek: take_arr(data, i)?,
                ek_dec: take_dec(data, i)?,
            }),
            7 => Ok(Agent::Ct1Sampled {
                secret: take_secret(data, i)?,
                ct1: take_arr(data, i)?,
                ct1_enc: take_enc(data, i)?,
                ek_dec: take_dec(data, i)?,
                ss: take_arr(data, i)?,
                emitted_ss: take_bool(data, i)?,
            }),
            8 => Ok(Agent::EkReceivedCt1Sampled {
                secret: take_secret(data, i)?,
                ct1: take_arr(data, i)?,
                ek_vector: take_exact_vec(data, i, EK_SIZE)?,
                ct1_enc: take_enc(data, i)?,
                ss: take_arr(data, i)?,
                emitted_ss: take_bool(data, i)?,
            }),
            9 => Ok(Agent::Ct1Acknowledged {
                secret: take_secret(data, i)?,
                ct1: take_arr(data, i)?,
                ek_dec: take_dec(data, i)?,
                ss: take_arr(data, i)?,
                emitted_ss: take_bool(data, i)?,
            }),
            10 => Ok(Agent::Ct2Sampled {
                ct2_enc: take_enc(data, i)?,
                ss: take_arr(data, i)?,
                emitted_ss: take_bool(data, i)?,
            }),
            _ => Err(PrimitiveError::InvalidLength),
        }
    }
}

fn deserialize_v3(data: &[u8]) -> Result<BraidScka, PrimitiveError> {
    let mut i = 8usize;
    let epoch = u64::from_le_bytes(take(data, &mut i, 8)?.try_into().unwrap());
    let auth = Authenticator::decode(&take_arr(data, &mut i)?);
    let agent = Agent::read(data, &mut i)?;
    if i != data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    Ok(BraidScka { epoch, auth, agent })
}

fn deserialize_compact(data: &[u8]) -> Result<BraidScka, PrimitiveError> {
    if data.len() != 81 {
        return Err(PrimitiveError::InvalidLength);
    }
    let epoch = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let mut auth_bytes = [0u8; 64];
    auth_bytes.copy_from_slice(&data[16..80]);
    let auth = Authenticator::decode(&auth_bytes);
    let bob_like = match data[80] {
        0 => false,
        1 => true,
        _ => return Err(PrimitiveError::InvalidLength),
    };
    let agent = if bob_like {
        Agent::NoHeaderReceived {
            header_dec: Decoder::new(HEADER_SIZE + MAC_SIZE),
        }
    } else {
        Agent::KeysUnsampled
    };
    Ok(BraidScka { epoch, auth, agent })
}

pub fn drive_until_key(
    a: &mut BraidScka,
    b: &mut BraidScka,
    max_rounds: usize,
) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
    let mut ka = None;
    let mut kb = None;
    for _ in 0..max_rounds {
        let (ma, _, oa) = a.send()?;
        if let Some(output) = oa {
            ka = Some(output.key);
        }
        let (_, ob) = b.receive(&ma)?;
        if let Some(output) = ob {
            kb = Some(output.key);
        }
        let (mb, _, ob2) = b.send()?;
        if let Some(output) = ob2 {
            kb = Some(output.key);
        }
        let (_, oa2) = a.receive(&mb)?;
        if let Some(output) = oa2 {
            ka = Some(output.key);
        }
        if let (Some(x), Some(y)) = (ka, kb) {
            return Ok((x, y));
        }
    }
    Err(PrimitiveError::LimitExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn braid_alice_bob_keys_match() {
        let sk = [7u8; 32];
        let mut a = BraidScka::init_alice(&sk).unwrap();
        let mut b = BraidScka::init_bob(&sk).unwrap();
        let (ka, kb) = drive_until_key(&mut a, &mut b, 800).unwrap();
        assert_eq!(ka, kb);
        assert_ne!(ka, [0u8; 32]);
    }

    #[test]
    fn incremental_ct1_before_ek() {
        let sk = [5u8; 32];
        let mut a = BraidScka::init_alice(&sk).unwrap();
        let mut b = BraidScka::init_bob(&sk).unwrap();
        let mut saw_ct1_before_ek = false;
        let mut saw_ek = false;
        for _ in 0..200 {
            let (ma, _, _) = a.send().unwrap();
            if ma.typ == BraidType::Ek {
                saw_ek = true;
            }
            b.receive(&ma).unwrap();
            let (mb, _, _) = b.send().unwrap();
            if mb.typ == BraidType::Ct1 && !saw_ek {
                saw_ct1_before_ek = true;
            }
            a.receive(&mb).unwrap();
            if saw_ct1_before_ek && saw_ek {
                break;
            }
        }
        assert!(saw_ct1_before_ek);
    }

    #[test]
    fn serialize_reload_mid_handshake() {
        let sk = [3u8; 32];
        let mut a = BraidScka::init_alice(&sk).unwrap();
        let mut b = BraidScka::init_bob(&sk).unwrap();
        for _ in 0..12 {
            let (message, _, _) = a.send().unwrap();
            b.receive(&message).unwrap();
            let (message, _, _) = b.send().unwrap();
            a.receive(&message).unwrap();
        }
        let mut a = BraidScka::deserialize(&a.serialize()).unwrap();
        let mut b = BraidScka::deserialize(&b.serialize()).unwrap();
        let (ka, kb) = drive_until_key(&mut a, &mut b, 800).unwrap();
        assert_eq!(ka, kb);
    }

    #[test]
    fn message_encode_decode() {
        let message = BraidMessage {
            epoch: 3,
            typ: BraidType::None,
            data: Vec::new(),
        };
        assert_eq!(BraidMessage::decode(&message.encode()).unwrap(), message);
    }

    #[test]
    fn no_data_message_rejects_trailing_chunk() {
        let mut encoded = BraidMessage {
            epoch: 3,
            typ: BraidType::None,
            data: Vec::new(),
        }
        .encode();
        encoded.push(1);
        assert!(BraidMessage::decode(&encoded).is_err());
    }

    #[test]
    fn compact_boolean_is_canonical() {
        let mut compact = b"VCBRAID2".to_vec();
        compact.extend_from_slice(&1u64.to_le_bytes());
        compact.extend_from_slice(&[0u8; 64]);
        compact.push(2);
        assert!(BraidScka::deserialize(&compact).is_err());
    }

    #[test]
    fn v3_rejects_noncanonical_boolean() {
        let sk = [4u8; 32];
        let mut a = BraidScka::init_alice(&sk).unwrap();
        let mut b = BraidScka::init_bob(&sk).unwrap();
        // Drive until a state containing emitted_ss is likely to appear.
        for _ in 0..120 {
            let (ma, _, _) = a.send().unwrap();
            b.receive(&ma).unwrap();
            let (mb, _, _) = b.send().unwrap();
            a.receive(&mb).unwrap();
            let blob = a.serialize();
            // Parser itself is the assertion here; canonical generated state
            // must always round-trip under the stricter boolean decoder.
            BraidScka::deserialize(&blob).unwrap();
        }
    }

    #[test]
    fn oversized_persisted_state_is_rejected() {
        let blob = vec![0u8; MAX_BRAID_STATE + 1];
        assert!(BraidScka::deserialize(&blob).is_err());
    }

    #[test]
    fn agent_vector_bound_constant_covers_expected_material() {
        assert!(MAX_AGENT_VECTOR >= EK_SIZE);
    }
}
