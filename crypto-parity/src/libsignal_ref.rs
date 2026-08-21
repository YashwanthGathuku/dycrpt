//! Isolated libsignal reference adapter.
//!
//! Never depends on `libsignal`. Reports [`Status::NotLinked`].

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NotLinked,
}

pub fn status() -> Status {
    Status::NotLinked
}

pub const LICENSE: &str = "AGPL-3.0 (do not link from this crate)";
pub const PIN_FILE: &str = "backends/libsignal/PIN.md";
