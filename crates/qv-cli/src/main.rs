//! Quantum Vault CLI — `qv`
//!
//! Commands:
//!   qv keygen   [--out-dir <dir>] [--backend dev|kpqc]
//!   qv encrypt  --in <file> --out <file> --pubkeys <k1,k2,...> --threshold <n> --sign-key <file> [--backend dev|kpqc]
//!   qv decrypt  --in <file> --out <file> --privkeys <k1,k2,...> --verify-key <file> [--backend dev|kpqc]

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand};
use qv_core::{
    container::QuantumVaultContainer,
    crypto::{
        backend::dev::{DevKem, DevSignature},
        kem::Kem,
        signature::Signature,
    },
    decrypt_file, encrypt_file, DecryptOptions, EncryptOptions,
};
#[cfg(any(feature = "kpqc-native", feature = "kpqc-wasm"))]
use qv_core::crypto::backend::kpqc::{KpqcKem, KpqcSignature};
use std::{
    fs,
    path::{Path, PathBuf},
};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "qv",
    version,
    about = "Quantum Vault — threshold + post-quantum encrypted file vault",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a KEM keypair and a signature keypair.
    Keygen {
        /// Directory to write key files into (default: current directory).
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        /// Prefix for generated key file names.
        #[arg(long, default_value = "qv-key")]
        name: String,
        /// Cryptographic backend to use: `dev` (default, testing only) or
        /// `kpqc` (SMAUG-T + HAETAE, requires kpqc-native or kpqc-wasm feature).
        #[arg(long, default_value = "dev")]
        backend: String,
    },

    /// Encrypt a file into a .qvault container.
    Encrypt {
        /// Plaintext input file.
        #[arg(long, short)]
        r#in: PathBuf,
        /// Output .qvault container file.
        #[arg(long, short)]
        out: PathBuf,
        /// Comma-separated base64-encoded KEM public keys (one per share).
        #[arg(long)]
        pubkeys: String,
        /// Minimum number of shares required to decrypt.
        #[arg(long, default_value = "2")]
        threshold: u8,
        /// Path to base64-encoded signing private key file.
        #[arg(long)]
        sign_key: PathBuf,
        /// Cryptographic backend: `dev` or `kpqc`.
        #[arg(long, default_value = "dev")]
        backend: String,
    },

    /// Decrypt a .qvault container.
    Decrypt {
        /// Input .qvault container file.
        #[arg(long, short)]
        r#in: PathBuf,
        /// Output plaintext file.
        #[arg(long, short)]
        out: PathBuf,
        /// Comma-separated base64-encoded KEM private keys (threshold or more).
        #[arg(long)]
        privkeys: String,
        /// Path to base64-encoded signature public key file (for verification).
        #[arg(long)]
        verify_key: PathBuf,
        /// Cryptographic backend: `dev` or `kpqc`.
        #[arg(long, default_value = "dev")]
        backend: String,
    },
}

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

/// Build boxed KEM + Signature implementations from a backend name string.
///
/// Returns an error if the requested backend is unknown or unavailable in the
/// current feature configuration.
fn build_backends(backend: &str) -> Result<(Box<dyn Kem>, Box<dyn Signature>)> {
    match backend {
        "dev" => Ok((Box::new(DevKem), Box::new(DevSignature))),
        "kpqc" => {
            #[cfg(not(any(feature = "kpqc-native", feature = "kpqc-wasm")))]
            return Err(anyhow!(
                "The `kpqc` backend is not available in this build.\n\
                 Compile with `--features kpqc-native` (requires vendored C source) \
                 or `--features kpqc-wasm`."
            ));
            #[cfg(any(feature = "kpqc-native", feature = "kpqc-wasm"))]
            Ok((Box::new(KpqcKem), Box::new(KpqcSignature)))
        }
        other => Err(anyhow!(
            "Unknown backend {:?}. Valid options: `dev`, `kpqc`.",
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen { out_dir, name, backend } => {
            let (kem, sig) = build_backends(&backend)?;
            cmd_keygen(kem.as_ref(), sig.as_ref(), &out_dir, &name)
        }
        Command::Encrypt {
            r#in,
            out,
            pubkeys,
            threshold,
            sign_key,
            backend,
        } => {
            let (kem, sig) = build_backends(&backend)?;
            cmd_encrypt(kem.as_ref(), sig.as_ref(), &r#in, &out, &pubkeys, threshold, &sign_key)
        }
        Command::Decrypt {
            r#in,
            out,
            privkeys,
            verify_key,
            backend,
        } => {
            let (kem, sig) = build_backends(&backend)?;
            cmd_decrypt(kem.as_ref(), sig.as_ref(), &r#in, &out, &privkeys, &verify_key)
        }
    }
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

fn cmd_keygen(kem: &dyn Kem, sig: &dyn Signature, out_dir: &Path, name: &str) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create output directory {}", out_dir.display()))?;

    // KEM keypair
    let (kem_pub, kem_priv) = kem.generate_keypair()?;
    let kem_pub_path = out_dir.join(format!("{name}.kem.pub"));
    let kem_priv_path = out_dir.join(format!("{name}.kem.priv"));
    write_b64(&kem_pub_path, &kem_pub)?;
    write_b64(&kem_priv_path, &kem_priv)?;
    eprintln!("KEM public key  → {}", kem_pub_path.display());
    eprintln!("KEM private key → {}", kem_priv_path.display());

    // Signature keypair
    let (sig_pub, sig_priv) = sig.generate_keypair()?;
    let sig_pub_path = out_dir.join(format!("{name}.sig.pub"));
    let sig_priv_path = out_dir.join(format!("{name}.sig.priv"));
    write_b64(&sig_pub_path, &sig_pub)?;
    write_b64(&sig_priv_path, &sig_priv)?;
    eprintln!("Sig public key  → {}", sig_pub_path.display());
    eprintln!("Sig private key → {}", sig_priv_path.display());

    println!("Backend: {} / {}", kem.algorithm_id(), sig.algorithm_id());
    Ok(())
}

// ---------------------------------------------------------------------------
// encrypt
// ---------------------------------------------------------------------------

fn cmd_encrypt(
    kem: &dyn Kem,
    sig: &dyn Signature,
    in_path: &Path,
    out_path: &Path,
    pubkeys_csv: &str,
    threshold: u8,
    sign_key_path: &Path,
) -> Result<()> {
    let plaintext = fs::read(in_path)
        .with_context(|| format!("failed to read input file {}", in_path.display()))?;

    let recipient_public_keys: Vec<Vec<u8>> = pubkeys_csv
        .split(',')
        .map(|s| B64.decode(s.trim()).map_err(|e| anyhow!("invalid base64 pubkey: {e}")))
        .collect::<Result<_>>()?;

    let share_count = recipient_public_keys.len() as u8;
    if threshold > share_count {
        return Err(anyhow!(
            "threshold ({threshold}) cannot exceed number of public keys ({share_count})"
        ));
    }

    let signer_private_key = read_b64(sign_key_path)
        .with_context(|| format!("failed to read signing key {}", sign_key_path.display()))?;

    let options = EncryptOptions {
        threshold,
        share_count,
        recipient_public_keys,
        signer_private_key,
    };

    let container = encrypt_file(&plaintext, &options, kem, sig)?;
    let bytes = container.to_bytes()?;

    fs::write(out_path, &bytes)
        .with_context(|| format!("failed to write container {}", out_path.display()))?;

    println!(
        "Encrypted {} bytes → {} ({} shares, threshold {})",
        plaintext.len(),
        out_path.display(),
        share_count,
        threshold,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// decrypt
// ---------------------------------------------------------------------------

fn cmd_decrypt(
    kem: &dyn Kem,
    sig: &dyn Signature,
    in_path: &Path,
    out_path: &Path,
    privkeys_csv: &str,
    verify_key_path: &Path,
) -> Result<()> {
    let container_bytes = fs::read(in_path)
        .with_context(|| format!("failed to read container {}", in_path.display()))?;

    let container = QuantumVaultContainer::from_bytes(&container_bytes)
        .with_context(|| format!("failed to parse container {}", in_path.display()))?;

    let recipient_private_keys: Vec<Vec<u8>> = privkeys_csv
        .split(',')
        .map(|s| B64.decode(s.trim()).map_err(|e| anyhow!("invalid base64 privkey: {e}")))
        .collect::<Result<_>>()?;

    let signer_public_key = read_b64(verify_key_path)
        .with_context(|| format!("failed to read verify key {}", verify_key_path.display()))?;

    let options = DecryptOptions {
        recipient_private_keys,
        signer_public_key,
    };

    let plaintext = decrypt_file(&container, &options, kem, sig)?;

    fs::write(out_path, &plaintext)
        .with_context(|| format!("failed to write plaintext {}", out_path.display()))?;

    println!(
        "Decrypted {} bytes → {}",
        plaintext.len(),
        out_path.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write `bytes` as base64 (standard, padded) to `path`.
fn write_b64(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, B64.encode(bytes))
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Read base64 bytes from `path`.
fn read_b64(path: &Path) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    B64.decode(s.trim())
        .map_err(|e| anyhow!("failed to decode base64 from {}: {e}", path.display()))
}
