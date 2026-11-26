//! Cross-platform device options and dry-run output.
//!
//! The device itself is macOS-only, but its CLI plan is not. Keeping these
//! values here lets the binary describe (and reject) `--run` on other targets
//! without compiling IOKit or LocalAuthentication code.

use crate::{DEFAULT_IDENTITY, FIDO_USAGE_CTAPHID, FIDO_USAGE_PAGE, REPORT_DESCRIPTOR};
use ctap2::{AttestationFormat, UvPolicy};
use se_fido_store::default_dir;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
pub use backend_se::StorageMode;

/// Storage mode for the CLI on non-macOS targets. The macOS build uses
/// `backend_se::StorageMode` directly so `--run` receives the exact type.
#[cfg(not(target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    Blob,
    Keychain,
}

#[cfg(not(target_os = "macos"))]
impl StorageMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "blob" => Some(StorageMode::Blob),
            "keychain" => Some(StorageMode::Keychain),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            StorageMode::Blob => "blob",
            StorageMode::Keychain => "keychain",
        }
    }
}

/// Runtime options for the virtual device (CLI flags / env).
#[derive(Debug, Clone)]
pub struct DeviceOptions {
    /// Default UV policy for new credentials.
    pub uv_policy: UvPolicy,
    /// Attestation format (affects whether MakeCredential will SE-prompt).
    pub attestation: AttestationFormat,
    /// DANGEROUS: skip LA/SE prompts and approve presence. Opt-in only.
    pub auto_approve: bool,
    /// Where SE keys live. Blob (default) needs no Keychain entitlement and
    /// works for ad-hoc signed binaries; Keychain is opt-in.
    pub storage: StorageMode,
}

impl Default for DeviceOptions {
    fn default() -> Self {
        DeviceOptions {
            uv_policy: UvPolicy::Presence,
            attestation: AttestationFormat::PackedSelf,
            auto_approve: false,
            storage: StorageMode::Blob,
        }
    }
}

/// Data directory: `$SE_FIDO_DIR` or the store default.
pub fn data_dir() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("SE_FIDO_DIR") {
        return Ok(PathBuf::from(p));
    }
    default_dir().ok_or_else(|| "HOME unset and SE_FIDO_DIR not set".into())
}

fn storage_note(mode: StorageMode) -> &'static str {
    match mode {
        StorageMode::Blob => "blob (SE key blobs in the data directory; no Keychain entitlement)",
        StorageMode::Keychain => {
            "keychain (data-protection Keychain; needs a keychain-access-groups entitlement)"
        }
    }
}

/// Human-readable plan of what `--run` would do. Does not create a device.
pub fn dry_run_text(opts: &DeviceOptions) -> String {
    let id = &DEFAULT_IDENTITY;
    let dir = data_dir().unwrap_or_else(|e| PathBuf::from(format!("<error: {e}>")));
    let auto = if opts.auto_approve {
        "ON (DANGEROUS: no LA/Touch ID)"
    } else {
        "off (LA for UP when SE will not prompt; SE ACL on sign for presence/biometry)"
    };
    format!(
        "se-fido-device dry run (pass --run to create and activate the virtual HID device)\n\
         \n\
         identity:\n\
           Product={}\n\
           Manufacturer={}\n\
           SerialNumber={}\n\
           VendorID=0x{:04x} (placeholder, not a USB-IF assignment)\n\
           ProductID=0x{:04x} (placeholder)\n\
           Transport={}\n\
           PrimaryUsagePage=0x{:04x}\n\
           PrimaryUsage=0x{:04x}\n\
           ReportDescriptor={} bytes\n\
         \n\
         data dir: {}\n\
         entitlement: com.apple.developer.hid.virtual.device\n\
         options: IOHIDUserDeviceOptionsCreateOnActivate\n\
         uv_policy: {} (default for new credentials)\n\
         attestation: {:?}\n\
         auto_approve: {}\n\
         storage: {}\n\
         \n\
         See DEPLOY.md for signing and SIP/AMFI steps before --run.\n\
         After deploy, probe Touch ID SE keys with: target/debug/se-probe --touchid\n",
        id.product,
        id.manufacturer,
        id.serial,
        id.vendor_id,
        id.product_id,
        id.transport,
        FIDO_USAGE_PAGE,
        FIDO_USAGE_CTAPHID,
        REPORT_DESCRIPTOR.len(),
        dir.display(),
        opts.uv_policy.as_str(),
        opts.attestation,
        auto,
        storage_note(opts.storage),
    )
}
