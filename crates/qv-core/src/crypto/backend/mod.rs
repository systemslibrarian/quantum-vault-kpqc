//! Concrete crypto backends.
//!
//! | Module       | Feature flag   | Algorithms |
//! |--------------|----------------|------------|
//! | [`dev`]      | `dev-backend`  | Dev stubs — SHA-256 / XOR, for testing only |
//! | [`kpqc`]     | `kpqc-native` or `kpqc-wasm` | SMAUG-T (KEM) + HAETAE (signature) |
//! | [`kpqc_ffi`] | `kpqc-native`  | Raw `extern "C"` wrappers for the C reference implementations |

pub mod dev;
pub mod kpqc;

#[cfg(feature = "kpqc-native")]
pub mod kpqc_ffi;

pub use dev::{DevKem, DevSignature};
pub use kpqc::{KpqcKem, KpqcSignature};
