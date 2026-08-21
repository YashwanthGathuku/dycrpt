//! `cargo run -p crypto-parity -- [--full]`

use crypto_parity::corpus;
use crypto_parity::libsignal_ref;
use crypto_parity::malformed;
use crypto_parity::randomized;
use crypto_parity::types::{Axis, Classification, Scorecard};
use crypto_parity::{format_scorecard, run_corpus};
use std::fs;
use std::path::Path;

fn main() {
    let full = std::env::args().any(|a| a == "--full");
    eprintln!(
        "crypto-parity: VoiceChatCrypto corpus ({} scenarios); libsignal={:?}",
        corpus::spec_count(),
        libsignal_ref::status()
    );

    let mut sc = run_corpus();

    let (rs, re) = if full { (200, 5000) } else { (40, 250) };
    eprintln!("randomized DR: {rs} sessions × {re} events");
    let rr = randomized::run_ratchet(rs, re, 0xC0FFEE);
    sc.random_transitions = rr.transitions;
    sc.random_violations = rr.violations;
    if !rr.notes.is_empty() {
        eprintln!("random notes: {:?}", rr.notes);
    }

    let (es, ee) = if full { (20, 40) } else { (8, 16) };
    eprintln!("randomized engine: {es} sessions × {ee} events");
    let er = randomized::run_engine(es, ee, 0xBEEF);
    sc.random_transitions += er.transitions;
    sc.random_violations += er.violations;

    let fz = malformed::run();
    sc.malformed_inputs = fz.inputs;
    sc.malformed_panics = fz.panics;

    let (core, _, _) = sc.axis_score(Axis::SignalCore);
    let (ops, _, _) = sc.axis_score(Axis::Operational);
    let (vc, _, _) = sc.axis_score(Axis::VoiceChat);
    let p0 = sc.p0_failures().len();

    let report_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("reports");
    let _ = fs::create_dir_all(&report_dir);
    fs::write(report_dir.join("SCORECARD.md"), format_scorecard(&sc)).ok();
    fs::write(report_dir.join("PARITY.md"), parity_md(&sc, full)).ok();
    fs::write(report_dir.join("failures.json"), failures_json(&sc)).ok();

    println!("{}", format_scorecard(&sc));
    println!(
        "gates: P0={} core={core:.1} ops={ops:.1} vc={vc:.1} random_viol={} fuzz_panic={}",
        p0, sc.random_violations, sc.malformed_panics
    );

    let fail = p0 > 0
        || core < 95.0
        || ops < 90.0
        || vc < 100.0
        || sc.random_violations > 0
        || sc.malformed_panics > 0;
    if fail {
        std::process::exit(1);
    }
}

fn parity_md(sc: &Scorecard, full: bool) -> String {
    let mut o = String::from("# PARITY.md\n\n");
    o.push_str("Backend under test: **VoiceChatCrypto**.\n");
    o.push_str("Reference backend: **NOT_LINKED** (libsignal AGPL isolated).\n\n");
    o.push_str(&format!(
        "Mode: {}\n\n",
        if full { "full" } else { "quick" }
    ));
    o.push_str("| id | category | axis | P0 | result | note |\n|---|---|---|---|---|---|\n");
    for r in &sc.results {
        let axis = match r.axis {
            Axis::SignalCore => "core",
            Axis::Operational => "ops",
            Axis::VoiceChat => "vc",
        };
        o.push_str(&format!(
            "| `{}` | {} | {} | {} | {:?} | {} |\n",
            r.id,
            r.category,
            axis,
            if r.p0 { "Y" } else { "" },
            if r.passed {
                Classification::Pass
            } else {
                r.class
            },
            r.note.replace('|', "/")
        ));
    }
    o
}

fn failures_json(sc: &Scorecard) -> String {
    let mut o = String::from("[\n");
    let fails: Vec<_> = sc.results.iter().filter(|r| !r.passed).collect();
    for (i, r) in fails.iter().enumerate() {
        o.push_str(&format!(
            "  {{\"id\":\"{}\",\"p0\":{},\"note\":\"{}\"}}",
            r.id,
            r.p0,
            r.note.replace('"', "'")
        ));
        if i + 1 != fails.len() {
            o.push(',');
        }
        o.push('\n');
    }
    o.push_str("]\n");
    o
}
