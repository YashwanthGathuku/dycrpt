//! Dudect-style statistical timing experiment for secret-dependent X25519 work.
//!
//! This is an empirical leakage detector, not a proof of constant time. Run it
//! on quiet, pinned physical x86_64 and ARM64 cores in release mode. It compares
//! two fixed secret classes under a common public input and fails when the
//! absolute Welch t statistic exceeds the configured threshold.

use std::hint::black_box;
use std::time::Instant;

use voicechat_crypto::primitives::x25519::{X25519Public, X25519Secret};

const OPS_PER_SAMPLE: usize = 16;

#[derive(Default)]
struct OnlineStats {
    n: u64,
    mean: f64,
    m2: f64,
}

impl OnlineStats {
    fn push(&mut self, value: f64) {
        self.n += 1;
        let delta = value - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    fn variance(&self) -> f64 {
        if self.n > 1 {
            self.m2 / (self.n - 1) as f64
        } else {
            0.0
        }
    }
}

fn welch_t(a: &OnlineStats, b: &OnlineStats) -> f64 {
    let denom = (a.variance() / a.n as f64 + b.variance() / b.n as f64).sqrt();
    if denom == 0.0 {
        if a.mean == b.mean {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        (a.mean - b.mean) / denom
    }
}

fn arg_value(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }
    }
    None
}

fn main() {
    let samples: usize = arg_value("--samples")
        .and_then(|v| v.parse().ok())
        .unwrap_or(250_000);
    let max_t: f64 = arg_value("--max-t")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10.0);
    let warmup: usize = arg_value("--warmup")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);

    if samples < 10_000 || !max_t.is_finite() || max_t <= 0.0 {
        eprintln!("invalid timing-test configuration");
        std::process::exit(2);
    }

    let secret_a = X25519Secret::from_bytes([0x00; 32]);
    let secret_b = X25519Secret::from_bytes([0xff; 32]);
    let mut base = [0u8; 32];
    base[0] = 9;
    let public = X25519Public::from_bytes(base).expect("X25519 basepoint must be valid");

    for i in 0..warmup {
        let secret = if i & 1 == 0 { &secret_a } else { &secret_b };
        let output = secret
            .diffie_hellman_checked(black_box(&public))
            .expect("basepoint DH must be contributory");
        black_box(output);
    }

    let mut classes = [OnlineStats::default(), OnlineStats::default()];
    let mut prng = 0x9e37_79b9_7f4a_7c15u64;

    for _ in 0..samples {
        // Randomized class order reduces slow thermal/frequency drift from being
        // correlated with a particular secret class.
        prng ^= prng << 13;
        prng ^= prng >> 7;
        prng ^= prng << 17;
        let class = (prng & 1) as usize;
        let secret = if class == 0 { &secret_a } else { &secret_b };

        let start = Instant::now();
        for _ in 0..OPS_PER_SAMPLE {
            let output = secret
                .diffie_hellman_checked(black_box(&public))
                .expect("basepoint DH must be contributory");
            black_box(output);
        }
        let ns_per_op = start.elapsed().as_nanos() as f64 / OPS_PER_SAMPLE as f64;
        classes[class].push(ns_per_op);
    }

    let t = welch_t(&classes[0], &classes[1]);
    let abs_t = t.abs();
    let passed = abs_t <= max_t;

    println!(
        concat!(
            "{{\"schema\":\"dycrpt-ct-v1\",",
            "\"arch\":\"{}\",\"os\":\"{}\",",
            "\"probe\":\"x25519-secret-class\",",
            "\"samples\":{},\"ops_per_sample\":{},",
            "\"class0_n\":{},\"class1_n\":{},",
            "\"class0_mean_ns\":{:.6},\"class1_mean_ns\":{:.6},",
            "\"welch_t\":{:.6},\"max_abs_t\":{:.6},\"passed\":{} }}"
        ),
        std::env::consts::ARCH,
        std::env::consts::OS,
        samples,
        OPS_PER_SAMPLE,
        classes[0].n,
        classes[1].n,
        classes[0].mean,
        classes[1].mean,
        t,
        max_t,
        passed
    );

    if !passed {
        eprintln!(
            "timing-leak gate failed: |t|={abs_t:.3} > {max_t:.3}; repeat on a quiet pinned core before triage"
        );
        std::process::exit(1);
    }
}
