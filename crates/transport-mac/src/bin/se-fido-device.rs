//! Virtual FIDO HID device process.
//!
//! Default: print what `--run` would do (no device is created).
//! `--run`: create and activate the IOHIDUserDevice (needs entitlement; see DEPLOY.md).
//!
//! Flags:
//!   --uv-policy=none|presence|biometry   default for new credentials (default presence)
//!   --attestation=packed|none
//!   --auto-approve   DANGEROUS: skip LA/Touch ID (opt-in, logged loudly)
//!   --storage=blob|keychain   where SE keys live (default blob, which works
//!                             ad-hoc signed; keychain needs an access group)

use ctap2::{AttestationFormat, UvPolicy};
use transport_mac::{dry_run_text, DeviceOptions, StorageMode};

fn diagnostic(message: &str) {
    eprintln!("se-fido-device: {message}");
}

fn main() {
    let mut opts = DeviceOptions::default();
    let mut run = false;
    for a in std::env::args().skip(1) {
        if a == "--run" {
            run = true;
        } else if a == "--auto-approve" {
            opts.auto_approve = true;
        } else if let Some(v) = a.strip_prefix("--uv-policy=") {
            opts.uv_policy = UvPolicy::parse(v).unwrap_or_else(|| {
                diagnostic(&format!("bad --uv-policy={v}"));
                std::process::exit(2);
            });
        } else if let Some(v) = a.strip_prefix("--attestation=") {
            opts.attestation = match v {
                "packed" => AttestationFormat::PackedSelf,
                "none" => AttestationFormat::None,
                _ => {
                    diagnostic(&format!("bad --attestation={v}"));
                    std::process::exit(2);
                }
            };
        } else if let Some(v) = a.strip_prefix("--storage=") {
            opts.storage = StorageMode::parse(v).unwrap_or_else(|| {
                diagnostic(&format!("bad --storage={v}"));
                std::process::exit(2);
            });
        } else if a == "--help" || a == "-h" {
            eprintln!(
                "usage: se-fido-device [--run] [--uv-policy=none|presence|biometry] [--attestation=packed|none] [--storage=blob|keychain] [--auto-approve]"
            );
            return;
        } else {
            diagnostic(&format!("unknown argument {a}"));
            std::process::exit(2);
        }
    }
    if !run {
        print!("{}", dry_run_text(&opts));
        return;
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: user passed --run after following DEPLOY.md.
        if let Err(e) = unsafe { transport_mac::device::run(&opts) } {
            diagnostic(&e);
            std::process::exit(1);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        diagnostic("--run requires macOS");
        std::process::exit(1);
    }
}
