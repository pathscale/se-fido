//! Fixture runner.
//!
//! `cargo run -p fixtures -- check`  replay every `fixtures/**/*.fx`, compare
//!                                   with `.expected` byte for byte and check
//!                                   `fixtures/MANIFEST` hashes.
//! `cargo run -p fixtures -- regen`  rewrite `.expected` files and MANIFEST.
//! `cargo run -p fixtures -- se`     opt-in end-to-end run on the real Secure
//!                                   Enclave (macOS, no prompts, not compared).
//!
//! Locations: `SE_FIDO_FIXTURES` (default `<workspace>/fixtures`) and
//! `SE_FIDO_TMPDIR` (default `<workspace>/.fixture-tmp`, gitignored).
//!
//! Every request line can carry assertions (`expect=Status`, `want=$n`, ...);
//! a failed assertion or a relying-party verification failure aborts the
//! fixture, so regenerated output cannot silently encode wrong behaviour.

mod ctap;
mod hid;
mod mac;
#[cfg(target_os = "macos")]
mod se;
mod store;
mod util;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Instant;

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn fixtures_dir() -> PathBuf {
    std::env::var_os("SE_FIDO_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace().join("fixtures"))
}

pub fn tmp_root() -> PathBuf {
    std::env::var_os("SE_FIDO_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace().join(".fixture-tmp"))
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|e| e == "fx") {
            out.push(p);
        }
    }
}

fn rel(base: &Path, p: &Path) -> String {
    p.strip_prefix(base)
        .unwrap_or(p)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn first_diff(a: &str, b: &str) -> String {
    for (i, (x, y)) in a.lines().zip(b.lines()).enumerate() {
        if x != y {
            return format!("line {}:\n    expected: {x}\n    actual:   {y}", i + 1);
        }
    }
    format!(
        "line counts differ: expected {} actual {}",
        a.lines().count(),
        b.lines().count()
    )
}

fn run(regen: bool) -> i32 {
    let base = fixtures_dir();
    let mut files = Vec::new();
    collect(&base, &mut files);
    if files.is_empty() {
        eprintln!("no fixtures under {}", base.display());
        return 1;
    }
    let tmp = tmp_root();
    let _ = fs::remove_dir_all(&tmp);
    let mut manifest = Vec::new();
    let mut failed = 0;
    let started = Instant::now();
    for f in &files {
        let name = rel(&base, f);
        let t = Instant::now();
        let input = match fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => {
                println!("FAIL {name}: {e}");
                failed += 1;
                continue;
            }
        };
        let category = name.split("/").next().unwrap_or("");
        let stem = name.trim_end_matches(".fx").replace("/", "-");
        let result = match category {
            "ctaphid" => hid::run(&input),
            "ctap2" => ctap::run(&input),
            "store" => store::run(&input, &tmp.join(&stem)),
            "transport-mac" => mac::run(&input),
            other => Err(format!("unknown fixture category {other}")),
        };
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        let out = match result {
            Ok(o) => o,
            Err(e) => {
                println!("FAIL {name}: {e}");
                failed += 1;
                continue;
            }
        };
        let exp_path = f.with_extension("expected");
        let exp_name = rel(&base, &exp_path);
        if regen {
            if let Err(e) = fs::write(&exp_path, &out) {
                println!("FAIL {name}: writing expected: {e}");
                failed += 1;
                continue;
            }
        } else {
            let expected = fs::read_to_string(&exp_path).unwrap_or_default();
            if expected != out {
                println!(
                    "FAIL {name}: output differs from {exp_name}, {}",
                    first_diff(&expected, &out)
                );
                failed += 1;
                continue;
            }
        }
        manifest.push(format!("{}  {name}", util::sha256_hex(input.as_bytes())));
        manifest.push(format!("{}  {exp_name}", util::sha256_hex(out.as_bytes())));
        println!(
            "ok   {name} ({} lines, sha256 {}, {ms:.1} ms)",
            out.lines().count(),
            &util::sha256_hex(out.as_bytes())[..16]
        );
    }
    let _ = fs::remove_dir_all(&tmp);
    manifest.sort_by(|a, b| a[66..].cmp(&b[66..]));
    let manifest = manifest.join("\n") + "\n";
    let mpath = base.join("MANIFEST");
    if failed == 0 {
        if regen {
            if let Err(e) = fs::write(&mpath, &manifest) {
                println!("FAIL MANIFEST: {e}");
                failed += 1;
            }
        } else if fs::read_to_string(&mpath).unwrap_or_default() != manifest {
            println!("FAIL MANIFEST: hashes differ (run regen and review)");
            failed += 1;
        }
    }
    println!(
        "{} fixtures, {} failed, MANIFEST sha256 {}, {:.1} ms total",
        files.len(),
        failed,
        &util::sha256_hex(manifest.as_bytes())[..16],
        started.elapsed().as_secs_f64() * 1000.0
    );
    (failed != 0) as i32
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    let code = match arg.as_str() {
        "check" => run(false),
        "regen" => run(true),
        #[cfg(target_os = "macos")]
        "se" => se::run(),
        _ => {
            eprintln!("usage: fixtures check|regen|se");
            2
        }
    };
    exit(code);
}
