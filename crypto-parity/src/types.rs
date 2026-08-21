//! Implementation-neutral outcome types.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Axis {
    SignalCore,
    Operational,
    VoiceChat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classification {
    Pass,
    Fail,
    IntentionalDifference,
    SpecVariant,
    Unknown,
    RefNotLinked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Accept,
    RejectAuth,
    RejectReplay,
    RejectIdentity,
    RejectLimit,
    RejectMalformed,
    SessionResetRequired,
}

#[derive(Clone, Debug)]
pub struct ScenarioResult {
    pub id: String,
    pub category: String,
    pub axis: Axis,
    pub weight: f64,
    pub p0: bool,
    pub passed: bool,
    pub class: Classification,
    pub note: String,
}

impl ScenarioResult {
    pub fn ok(id: &str, cat: &str, axis: Axis, weight: f64, p0: bool) -> Self {
        Self {
            id: id.into(),
            category: cat.into(),
            axis,
            weight,
            p0,
            passed: true,
            class: Classification::Pass,
            note: String::new(),
        }
    }

    pub fn fail(
        id: &str,
        cat: &str,
        axis: Axis,
        weight: f64,
        p0: bool,
        note: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            category: cat.into(),
            axis,
            weight,
            p0,
            passed: false,
            class: Classification::Fail,
            note: note.into(),
        }
    }
}

pub struct Scorecard {
    pub results: Vec<ScenarioResult>,
    pub random_transitions: u64,
    pub random_violations: u64,
    pub malformed_inputs: u64,
    pub malformed_panics: u64,
}

impl Scorecard {
    pub fn axis_score(&self, axis: Axis) -> (f64, usize, usize) {
        let mut w = 0.0;
        let mut p = 0.0;
        let mut n = 0usize;
        let mut ok = 0usize;
        for r in &self.results {
            if r.axis != axis {
                continue;
            }
            n += 1;
            w += r.weight;
            if r.passed {
                ok += 1;
                p += r.weight;
            }
        }
        let pct = if w == 0.0 { 100.0 } else { 100.0 * p / w };
        (pct, ok, n)
    }

    pub fn p0_failures(&self) -> Vec<&ScenarioResult> {
        self.results.iter().filter(|r| r.p0 && !r.passed).collect()
    }
}
