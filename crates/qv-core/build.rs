//! build.rs for qv-core
//!
//! Under default conditions this script does nothing: the dev backend needs no
//! external libraries.
//!
//! When compiled with `--features kpqc-native` it tries to locate the SMAUG-T
//! and HAETAE reference C implementations and compile them into the crate using
//! the `cc` crate.  If the source directories are not found the build fails
//! with a human-readable error message rather than an obscure linker error.
//!
//! # Locating the source trees
//!
//! The build script checks:
//! 1. Environment variables `SMAUG_T_SRC` and `HAETAE_SRC` (absolute paths).
//! 2. `vendor/smaug-t/` and `vendor/haetae/` relative to the workspace root
//!    (`CARGO_MANIFEST_DIR/../..`).
//!
//! ## How to obtain the reference implementations
//!
//! The SMAUG-T and HAETAE reference implementations are distributed through
//! the KpqC competition: <https://kpqc.or.kr/competition.html>
//!
//! There is no official public GitHub mirror.  Download the submission
//! packages from the KpqC website, extract them, and place the source trees
//! at:
//!
//! ```text
//! vendor/smaug-t/   ← extracted SMAUG-T reference implementation
//! vendor/haetae/    ← extracted HAETAE reference implementation
//! ```
//!
//! Then build with:
//! ```sh
//! cargo build -p qv-core --features kpqc-native
//! # or for the full workspace:
//! cargo build --features kpqc-native
//! ```
//!
//! # Security level selection
//!
//! The default security level is Level 3 (128-bit post-quantum / 192-bit
//! classical for SMAUG-T; Level 3 for HAETAE).  Override via env vars:
//!   `SMAUG_T_LEVEL=1|3|5`
//!   `HAETAE_LEVEL=2|3|5`

fn main() {
    // Re-run this script if these env vars change.
    println!("cargo:rerun-if-env-changed=SMAUG_T_SRC");
    println!("cargo:rerun-if-env-changed=HAETAE_SRC");
    println!("cargo:rerun-if-env-changed=SMAUG_T_LEVEL");
    println!("cargo:rerun-if-env-changed=HAETAE_LEVEL");

    #[cfg(feature = "kpqc-native")]
    compile_kpqc_native();
}

/// Compile and link the SMAUG-T and HAETAE reference C implementations.
///
/// Only called when the `kpqc-native` feature is active.
#[cfg(feature = "kpqc-native")]
fn compile_kpqc_native() {
    use std::{env, path::PathBuf};

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // workspace root is two levels up from crates/qv-core
    let workspace_root = manifest_dir.join("../..").canonicalize()
        .expect("could not resolve workspace root from CARGO_MANIFEST_DIR");

    // ── SMAUG-T ──────────────────────────────────────────────────────────────
    let smaug_src = env::var("SMAUG_T_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("vendor/smaug-t"));

    let smaug_level: u8 = env::var("SMAUG_T_LEVEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    if !smaug_src.exists() {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  SMAUG-T source not found — kpqc-native build failed    ║");
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        eprintln!("║  Expected:  {}  ║",
            smaug_src.display());
        eprintln!("║  Override:  export SMAUG_T_SRC=/path/to/SMAUG-T         ║");
        eprintln!("║  Source:    https://kpqc.or.kr/competition.html                         ║");
        eprintln!("║  Extract the SMAUG-T package and place it at vendor/smaug-t/               ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        eprintln!();
        std::process::exit(1);
    }

    compile_smaug_t(&smaug_src, smaug_level);

    // ── HAETAE ───────────────────────────────────────────────────────────────
    let haetae_src = env::var("HAETAE_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("vendor/haetae"));

    let haetae_level: u8 = env::var("HAETAE_LEVEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    if !haetae_src.exists() {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  HAETAE source not found — kpqc-native build failed     ║");
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        eprintln!("║  Expected:  {}   ║",
            haetae_src.display());
        eprintln!("║  Override:  export HAETAE_SRC=/path/to/HAETAE           ║");
        eprintln!("║  Source:    https://kpqc.or.kr/competition.html                        ║");
        eprintln!("║  Extract the HAETAE package and place it at vendor/haetae/               ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        eprintln!();
        std::process::exit(1);
    }

    compile_haetae(&haetae_src, haetae_level);
}

/// Compile SMAUG-T reference C code using the `cc` crate.
///
/// # Source layout assumption
///
/// The SMAUG-T reference repository is expected to have the following layout
/// (based on the KpqC competition reference submission layout):
///
/// ```
/// vendor/smaug-t/
/// ├── Reference_Implementation/
/// │   └── crypto_kem/
/// │       └── smaug-t<LEVEL>/
/// │           ├── api.h
/// │           ├── bch.c / bch.h
/// │           ├── drbg.c / drbg.h
/// │           ├── indcpa.c / indcpa.h
/// │           ├── kem.c
/// │           ├── pack.c / pack.h
/// │           ├── poly.c / poly.h
/// │           ├── ringct.c / ringct.h
/// │           └── symmetric.c / symmetric.h
/// ```
///
/// If the layout differs (e.g. a cmake-based subproject), adjust this function
/// accordingly.
#[cfg(feature = "kpqc-native")]
fn compile_smaug_t(src: &std::path::Path, level: u8) {
    use std::path::Path;

    // Validate security level.
    assert!(
        matches!(level, 1 | 3 | 5),
        "SMAUG_T_LEVEL must be 1, 3, or 5; got {level}"
    );

    let ref_dir = src
        .join("Reference_Implementation")
        .join("crypto_kem")
        .join(format!("smaug-t{level}"));

    if !ref_dir.exists() {
        eprintln!(
            "build.rs: SMAUG-T level-{level} reference directory not found: {}",
            ref_dir.display()
        );
        eprintln!("build.rs: Available paths under {}:", src.display());
        if let Ok(entries) = std::fs::read_dir(src) {
            for e in entries.flatten() {
                eprintln!("  {}", e.path().display());
            }
        }
        std::process::exit(1);
    }

    // Collect .c files from the level directory.
    let c_files: Vec<_> = std::fs::read_dir(&ref_dir)
        .expect("could not read SMAUG-T source dir")
        .flatten()
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "c"))
        .map(|e| e.path())
        .collect();

    if c_files.is_empty() {
        eprintln!(
            "build.rs: no .c files found in {} — check the SMAUG-T source layout",
            ref_dir.display()
        );
        std::process::exit(1);
    }

    let mut build = cc::Build::new();
    build
        .include(&ref_dir)
        .flag_if_supported("-O2")
        .flag_if_supported("-std=c99")
        .flag_if_supported("-Wall");

    for f in &c_files {
        build.file(f);
        println!("cargo:rerun-if-changed={}", f.display());
    }

    build.compile("smaug_t");
    println!("cargo:rustc-link-lib=static=smaug_t");
}

/// Compile HAETAE reference C code using the `cc` crate.
///
/// # Source layout assumption
///
/// ```
/// vendor/haetae/
/// ├── Reference_Implementation/
/// │   └── crypto_sign/
/// │       └── haetae<LEVEL>/
/// │           ├── api.h
/// │           ├── aes256ctr.c / .h
/// │           ├── fips202.c / .h
/// │           ├── haetae.c
/// │           ├── ntt.c / .h
/// │           ├── packing.c / .h
/// │           ├── params.h
/// │           ├── poly.c / .h
/// │           ├── polymat.c / .h
/// │           ├── polyvec.c / .h
/// │           ├── randombytes.c / .h
/// │           ├── reduce.c / .h
/// │           ├── rounding.c / .h
/// │           ├── sampler.c / .h
/// │           └── sign.c
/// ```
#[cfg(feature = "kpqc-native")]
fn compile_haetae(src: &std::path::Path, level: u8) {
    // Validate security level.
    assert!(
        matches!(level, 2 | 3 | 5),
        "HAETAE_LEVEL must be 2, 3, or 5; got {level}"
    );

    let ref_dir = src
        .join("Reference_Implementation")
        .join("crypto_sign")
        .join(format!("haetae{level}"));

    if !ref_dir.exists() {
        eprintln!(
            "build.rs: HAETAE level-{level} reference directory not found: {}",
            ref_dir.display()
        );
        std::process::exit(1);
    }

    let c_files: Vec<_> = std::fs::read_dir(&ref_dir)
        .expect("could not read HAETAE source dir")
        .flatten()
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "c"))
        .map(|e| e.path())
        .collect();

    if c_files.is_empty() {
        eprintln!(
            "build.rs: no .c files found in {} — check the HAETAE source layout",
            ref_dir.display()
        );
        std::process::exit(1);
    }

    let mut build = cc::Build::new();
    build
        .include(&ref_dir)
        .flag_if_supported("-O2")
        .flag_if_supported("-std=c99")
        .flag_if_supported("-Wall");

    for f in &c_files {
        build.file(f);
        println!("cargo:rerun-if-changed={}", f.display());
    }

    build.compile("haetae");
    println!("cargo:rustc-link-lib=static=haetae");
}
