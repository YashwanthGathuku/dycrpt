//! Randomized invariant simulation (per-backend; no cross-wire compare).

use crate::helpers::{dr_pair, engine_handshake, engine_named};
use voicechat_crypto::engine::CryptoEngineApi;
use voicechat_crypto::ratchet::DoubleRatchetState;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.0
    }
    fn pick(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

pub struct RandomReport {
    pub transitions: u64,
    pub violations: u64,
    pub notes: Vec<String>,
}

/// Classical DR event loop. Fast enough to approach 1e6 transitions.
pub fn run_ratchet(sessions: u32, events: u32, seed: u64) -> RandomReport {
    let mut rng = Rng(seed | 1);
    let mut transitions = 0u64;
    let mut violations = 0u64;
    let mut notes = Vec::new();
    for s in 0..sessions {
        let Ok((mut a, mut b)) = dr_pair() else {
            violations += 1;
            notes.push(format!("session {s} init failed"));
            continue;
        };
        let mut held_a: Vec<(voicechat_crypto::ratchet::Header, Vec<u8>)> = Vec::new();
        let mut held_b = Vec::new();
        for _ in 0..events {
            transitions += 1;
            match rng.pick(8) {
                0 => {
                    if let Ok(m) = a.encrypt(b"x", b"ad") {
                        held_a.push(m);
                    }
                }
                1 => {
                    if let Ok(m) = b.encrypt(b"y", b"ad") {
                        held_b.push(m);
                    }
                }
                2 => {
                    if !held_a.is_empty() {
                        let i = rng.pick(held_a.len() as u64) as usize;
                        let (h, c) = held_a.remove(i);
                        let _ = b.decrypt(&h, &c, b"ad");
                    }
                }
                3 => {
                    if !held_b.is_empty() {
                        let i = rng.pick(held_b.len() as u64) as usize;
                        let (h, c) = held_b.remove(i);
                        let _ = a.decrypt(&h, &c, b"ad");
                    }
                }
                4 => {
                    if !held_a.is_empty() {
                        let i = rng.pick(held_a.len() as u64) as usize;
                        let (h, mut c) = held_a[i].clone();
                        if let Some(x) = c.last_mut() {
                            *x ^= 1;
                        }
                        let before = b.serialize();
                        if b.decrypt(&h, &c, b"ad").is_ok() {
                            violations += 1;
                            notes.push("tamper accepted".into());
                        } else if b.serialize() != before {
                            violations += 1;
                            notes.push("tamper advanced state".into());
                        }
                    }
                }
                5 => {
                    if !held_a.is_empty() {
                        let (h, c) = held_a[0].clone();
                        let _ = b.decrypt(&h, &c, b"ad");
                    }
                }
                6 => {
                    if let Ok(blob) = Ok::<_, ()>(a.serialize()) {
                        if let Ok(a2) = DoubleRatchetState::deserialize(&blob, 1000) {
                            a = a2;
                        }
                    }
                }
                _ => {
                    if let Ok(blob) = Ok::<_, ()>(b.serialize()) {
                        if let Ok(b2) = DoubleRatchetState::deserialize(&blob, 1000) {
                            b = b2;
                        }
                    }
                }
            }
            if notes.len() > 8 {
                break;
            }
        }
        if notes.len() > 8 {
            break;
        }
    }
    RandomReport {
        transitions,
        violations,
        notes,
    }
}

/// Engine-level events (slower; smaller default).
pub fn run_engine(sessions: u32, events: u32, seed: u64) -> RandomReport {
    let mut rng = Rng(seed | 3);
    let mut transitions = 0u64;
    let mut violations = 0u64;
    let mut notes = Vec::new();
    for s in 0..sessions {
        let Ok(mut a) = engine_named(&[s as u8, 1]) else {
            violations += 1;
            continue;
        };
        let Ok(mut b) = engine_named(&[s as u8, 2]) else {
            violations += 1;
            continue;
        };
        let Ok((sa, sb)) = engine_handshake(&mut a, &mut b) else {
            violations += 1;
            notes.push(format!("engine handshake {s} failed"));
            continue;
        };
        let mut held = Vec::new();
        for _ in 0..events {
            transitions += 1;
            match rng.pick(6) {
                0 => {
                    if let Ok(m) = a.encrypt(&sa, b"x", b"ad") {
                        held.push(m);
                    }
                }
                1 => {
                    if let Ok(m) = b.encrypt(&sb, b"y", b"ad") {
                        held.push(m);
                    }
                }
                2 => {
                    if !held.is_empty() {
                        let i = rng.pick(held.len() as u64) as usize;
                        let m = held.remove(i);
                        let _ = b.decrypt(&sb, &m, b"ad");
                        let _ = a.decrypt(&sa, &m, b"ad");
                    }
                }
                3 => {
                    if !held.is_empty() {
                        let mut m = held[0].clone();
                        if let Some(x) = m.ciphertext.last_mut() {
                            *x ^= 1;
                        }
                        if b.decrypt(&sb, &m, b"ad").is_ok() && a.decrypt(&sa, &m, b"ad").is_ok() {
                            violations += 1;
                            notes.push("engine tamper accepted both sides".into());
                        }
                    }
                }
                4 => {
                    let _ = a.simulate_crash_reload();
                    let _ = b.simulate_crash_reload();
                }
                _ => {
                    if !held.is_empty() {
                        let m = held[0].clone();
                        let _ = b.decrypt(&sb, &m, b"ad");
                    }
                }
            }
            if notes.len() > 8 {
                break;
            }
        }
    }
    RandomReport {
        transitions,
        violations,
        notes,
    }
}
