//! Clean-room JSONL oracle for external behavioral differential testing.
//!
//! This binary links only dycrpt. A libsignal/reference adapter must live in a
//! separate AGPL-compatible workspace and emit the same implementation-neutral
//! protocol. The parent differential runner compares process outputs; no
//! libsignal code or data structure is linked into this permissive workspace.

use crypto_parity::corpus;
use crypto_parity::types::{Axis, Classification};
use std::env;

fn esc(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn axis(axis: Axis) -> &'static str {
    match axis {
        Axis::SignalCore => "signal-core",
        Axis::Operational => "operational",
        Axis::VoiceChat => "voicechat",
    }
}

fn class(class: Classification) -> &'static str {
    match class {
        Classification::Pass => "pass",
        Classification::Fail => "fail",
        Classification::IntentionalDifference => "intentional-difference",
        Classification::SpecVariant => "spec-variant",
        Classification::Unknown => "unknown",
        Classification::RefNotLinked => "reference-not-linked",
    }
}

fn main() {
    let commit = env::var("DYCRPT_COMMIT").unwrap_or_else(|_| "unknown".to_owned());
    let valid_commit = commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit());
    if !valid_commit {
        eprintln!("DYCRPT_COMMIT must contain the exact 40-character candidate SHA");
        std::process::exit(2);
    }

    println!(
        "{{\"type\":\"metadata\",\"schema\":\"dycrpt-external-oracle-v1\",\"implementation\":\"dycrpt\",\"commit\":\"{}\",\"protocol_family\":\"Signal-public-specs\",\"private_material_logged\":false}}",
        esc(&commit)
    );

    let mut failures = 0usize;
    for result in corpus::run_all() {
        if !result.passed {
            failures += 1;
        }
        println!(
            "{{\"type\":\"scenario\",\"id\":\"{}\",\"category\":\"{}\",\"axis\":\"{}\",\"p0\":{},\"status\":\"{}\",\"classification\":\"{}\",\"note\":\"{}\"}}",
            esc(&result.id),
            esc(&result.category),
            axis(result.axis),
            result.p0,
            if result.passed { "pass" } else { "fail" },
            class(result.class),
            esc(&result.note),
        );
    }

    println!(
        "{{\"type\":\"summary\",\"scenarios\":{},\"failures\":{}}}",
        corpus::spec_count(),
        failures
    );

    if failures != 0 {
        std::process::exit(1);
    }
}
