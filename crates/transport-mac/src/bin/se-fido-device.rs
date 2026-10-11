//! Virtual FIDO HID device process.
//!
//! Default: print what `--run` would do (no device is created).
//! `--run`: create and activate the IOHIDUserDevice (needs entitlement; see DEPLOY.md).

fn main() {
    let run = std::env::args().any(|a| a == "--run");
    if !run {
        print!("{}", transport_mac::device::dry_run_text());
        return;
    }
    // SAFETY: user passed --run after following DEPLOY.md.
    if let Err(e) = unsafe { transport_mac::device::run() } {
        eprintln!("se-fido-device: {e}");
        std::process::exit(1);
    }
}
