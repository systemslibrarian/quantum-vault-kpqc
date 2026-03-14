//! Pluggable cryptography abstraction layer.
//!
//! Concrete backends live in [`backend`].  The default, always-available
//! backend is [`backend::dev`] (development/testing only).  A future
//! production backend [`backend::kpqc`] will wire in SMAUG-T and HAETAE.

pub mod backend;
pub mod kem;
pub mod signature;

pub use backend::dev::{DevKem, DevSignature};
