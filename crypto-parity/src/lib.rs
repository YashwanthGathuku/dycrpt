//! Behavioral/security parity harness.
//!
//! Does **not** compare ciphertext or SK bytes across implementations.
//! Does **not** depend on libsignal (AGPL).

pub mod corpus;
pub mod helpers;
pub mod libsignal_ref;
pub mod malformed;
pub mod randomized;
pub mod types;

use crate::types::{Axis, Scorecard};

pub fn run_corpus() -> Scorecard {
    Scorecard {
        results: corpus::run_all(),
        random_transitions: 0,
        random_violations: 0,
        malformed_inputs: 0,
        malformed_panics: 0,
    }
}

pub fn format_scorecard(sc: &Scorecard) -> String {
    let (core, core_ok, core_n) = sc.axis_score(Axis::SignalCore);
    let (ops, ops_ok, ops_n) = sc.axis_score(Axis::Operational);
    let (vc, vc_ok, vc_n) = sc.axis_score(Axis::VoiceChat);
    let p0 = sc.p0_failures();
    let mut o = String::new();
    o.push_str("# Crypto parity scorecard\n\n");
    o.push_str("**Not a code-similarity score.** Outcomes are security properties.\n");
    o.push_str(
        "**Not wire-compatible with Signal.** SK/CT bytes are not compared across backends.\n\n",
    );
    o.push_str(&format!(
        "| Axis | Score | Passed |\n|---|---:|---:|\n| Signal-Core | {core:.1}% | {core_ok}/{core_n} |\n| Operational hardening | {ops:.1}% | {ops_ok}/{ops_n} |\n| VoiceChat invariants | {vc:.1}% | {vc_ok}/{vc_n} |\n\n"
    ));
    o.push_str(&format!("P0 failures: **{}**\n\n", p0.len()));
    if !p0.is_empty() {
        o.push_str("### P0 failures\n\n");
        for r in p0 {
            o.push_str(&format!("- `{}`: {}\n", r.id, r.note));
        }
        o.push('\n');
    }
    o.push_str(&format!(
        "Randomized transitions: {} (violations {})\n\n",
        sc.random_transitions, sc.random_violations
    ));
    o.push_str(&format!(
        "Malformed inputs: {} (panics {})\n\n",
        sc.malformed_inputs, sc.malformed_panics
    ));
    o.push_str(
        "libsignal backend: **NOT_LINKED** (AGPL isolated; see `backends/libsignal/PIN.md`).\n",
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_runs() {
        let sc = run_corpus();
        assert!(
            sc.results.len() >= 60,
            "need ≥60 scenarios, got {}",
            sc.results.len()
        );
        assert!(
            sc.p0_failures().is_empty(),
            "P0 failures: {:?}",
            sc.p0_failures()
                .iter()
                .map(|r| format!("{}: {}", r.id, r.note))
                .collect::<Vec<_>>()
        );
    }
}
