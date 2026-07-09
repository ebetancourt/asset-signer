//! Offline asset-bundle verifier.
//!
//! Trust model (proof of concept): a single public key is compiled into this
//! binary. Verification is two layers:
//!
//!   1. The bundle's `manifest.txt.minisig` is a minisign signature over
//!      `manifest.txt`, checked against the embedded key. If this fails,
//!      nothing else is trusted.
//!   2. Each `sha256  filename` line in the (now-trusted) manifest is checked
//!      against the actual file on disk.
//!
//! No network access is required or performed. The only thing that roots the
//! whole chain is the authenticity of THIS binary -- ship it over a channel
//! you trust (code signing / OS package manager / HTTPS you control).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};

/// The bundle signing public key (base64, i.e. the SECOND line of bundle.pub).
///
/// Replace this with the line printed by `asset_signer keygen`. The value
/// below is a placeholder and will not verify real bundles.
const PUBLIC_KEY: &str = "RWTLup2LeqFg6iwSPxegsSr8notkZW58NsEuNhdgEoJSURBQm+gc2owy";

const MANIFEST: &str = "manifest.txt";
const SIGNATURE: &str = "manifest.txt.minisig";

#[derive(Debug)]
enum VerifyError {
    Io(String),
    BadKey(String),
    BadSignature(String),
    SignatureInvalid,
    ManifestMalformed(String),
    MissingAsset(String),
    HashMismatch { name: String },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Io(e) => write!(f, "io error: {e}"),
            VerifyError::BadKey(e) => write!(f, "embedded public key is invalid: {e}"),
            VerifyError::BadSignature(e) => write!(f, "signature file is malformed: {e}"),
            VerifyError::SignatureInvalid => {
                write!(f, "manifest signature does NOT match the embedded key")
            }
            VerifyError::ManifestMalformed(l) => write!(f, "malformed manifest line: {l:?}"),
            VerifyError::MissingAsset(n) => write!(f, "asset listed in manifest is missing: {n}"),
            VerifyError::HashMismatch { name } => {
                write!(f, "asset failed hash check: {name}")
            }
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Verify a bundle directory. Returns the list of verified asset filenames.
fn verify_bundle(dir: &Path) -> Result<Vec<String>, VerifyError> {
    let manifest_path = dir.join(MANIFEST);
    let sig_path = dir.join(SIGNATURE);

    let public_key =
        PublicKey::from_base64(PUBLIC_KEY).map_err(|e| VerifyError::BadKey(e.to_string()))?;

    let sig_str =
        fs::read_to_string(&sig_path).map_err(|e| VerifyError::Io(format!("{SIGNATURE}: {e}")))?;
    let signature =
        Signature::decode(&sig_str).map_err(|e| VerifyError::BadSignature(e.to_string()))?;

    let manifest_bytes =
        fs::read(&manifest_path).map_err(|e| VerifyError::Io(format!("{MANIFEST}: {e}")))?;

    // Layer 1: signature over the manifest. `false` = do not allow legacy
    // (non-prehashed) signatures; our signer always uses prehashed mode.
    public_key
        .verify(&manifest_bytes, &signature, false)
        .map_err(|_| VerifyError::SignatureInvalid)?;

    // Layer 2: every asset matches its hash in the now-trusted manifest.
    let manifest_text =
        String::from_utf8(manifest_bytes).map_err(|e| VerifyError::Io(e.to_string()))?;

    let mut verified = Vec::new();
    for line in manifest_text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Format: "<64-hex>  <filename>"  (two spaces, sha256sum style)
        let (expected, name) = line
            .split_once("  ")
            .ok_or_else(|| VerifyError::ManifestMalformed(line.to_string()))?;
        let expected = expected.trim();
        let name = name.trim();

        let asset_path = dir.join(name);
        let bytes = fs::read(&asset_path).map_err(|_| VerifyError::MissingAsset(name.to_string()))?;
        let got = sha256_hex(&bytes);
        if got != expected {
            return Err(VerifyError::HashMismatch {
                name: name.to_string(),
            });
        }
        verified.push(name.to_string());
    }

    Ok(verified)
}

fn print_usage(program: &str) {
    eprintln!("usage: {program} <bundle-dir>");
    eprintln!();
    eprintln!("Verifies manifest.txt.minisig against the embedded public key,");
    eprintln!("then checks every asset's SHA-256 against manifest.txt.");
    eprintln!("Exit 0 = all verified, non-zero = verification failed.");
}

fn main() -> ExitCode {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "asset-verify".into());
    let dir: PathBuf = match args.next() {
        Some(d) => PathBuf::from(d),
        None => {
            print_usage(&program);
            return ExitCode::from(2);
        }
    };

    match verify_bundle(&dir) {
        Ok(assets) => {
            println!("OK: bundle verified ({} assets)", assets.len());
            for a in assets {
                println!("  verified: {a}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256 of "abc"
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
