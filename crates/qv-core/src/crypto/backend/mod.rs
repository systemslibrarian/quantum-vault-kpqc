//! Concrete crypto backends.
//!
//! | Module | Status | Algorithms |
//! |--------|--------|-----------|
//! | [`dev`]  | Ready  | Dev stubs — for testing only, no real security |
//! | [`kpqc`] | Scaffold | SMAUG-T (KEM) + HAETAE (signature) — not yet integrated |

pub mod dev;
pub mod kpqc;

pub use dev::{DevKem, DevSignature};
