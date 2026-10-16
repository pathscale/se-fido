//! Store fixtures: FileStore in a scratch directory with a deterministic key
//! and deterministic nonces, so file bytes and hashes are reproducible.
//!
//! Commands: `key WORD`, `open [capacity=N]`, `insert id=WORD rp=RP [rk]`,
//! `remove id=WORD`, `get id=WORD`, `list rp=RP`, `clear`, `count`,
//! `counter`, `files`, `tamper file=NAME at=OFFSET`, `write file=NAME hex=HEX`,
//! `setcounter N`, `absent file=NAME text=TEXT`.
//! Assertion: `expect=Ok|Full|Corrupt|Io|CounterExhausted|Missing`.

use crate::util::{sha256, sha256_hex, unhex, Args};
use ctap2::{Bytes, Credential, CredentialStore, StoreError, TestDrbg, Text};
use se_fido_store::{check_environment_secrets, FileStore, ENVIRONMENT_SECRET_REFUSAL};
use std::fmt::Write;
use std::fs;
use std::path::Path;
use std::sync::Arc;

fn err_kind(e: &StoreError) -> &'static str {
    match e {
        StoreError::Full => "Full",
        StoreError::Io(message) if message == ENVIRONMENT_SECRET_REFUSAL => "EnvironmentSecret",
        StoreError::Io(_) => "Io",
        StoreError::Corrupt(_) => "Corrupt",
        StoreError::CounterExhausted => "CounterExhausted",
    }
}

fn cred(word: &str, rp: &str, rk: bool, created: u64) -> Credential {
    let id = sha256(word.as_bytes());
    let mut pk = vec![4u8];
    pk.extend_from_slice(&sha256(format!("x{word}").as_bytes()));
    pk.extend_from_slice(&sha256(format!("y{word}").as_bytes()));
    Credential {
        id: Bytes::copy_from_slice(&id),
        rp_id: Text::from(rp),
        rp_name: Some(Text::from("Example")),
        user_id: Bytes::copy_from_slice(word.as_bytes()),
        user_name: if rk {
            Some(Text::from("alice@example.com"))
        } else {
            None
        },
        user_display_name: None,
        key_handle: Bytes::copy_from_slice(&sha256(format!("kh{word}").as_bytes())[..16]),
        public_key: Bytes::from(pk),
        discoverable: rk,
        created,
        uv_policy: ctap2::UvPolicy::Presence,
    }
}

fn show(c: &Credential) -> String {
    format!(
        "id={} rp={} user={} rk={} created={} name={}",
        &ctap2::hex(&c.id)[..16],
        c.rp_id,
        ctap2::hex(&c.user_id),
        c.discoverable,
        c.created,
        c.user_name.as_ref().map(|t| t.as_str()).unwrap_or("-")
    )
}

fn file_line(dir: &Path, name: &str) -> String {
    match fs::read(dir.join(name)) {
        Ok(b) => {
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(dir.join(name))
                    .map(|m| format!("{:o}", m.permissions().mode() & 0o777))
                    .unwrap_or_default()
            };
            #[cfg(not(unix))]
            let mode = String::from("-");
            format!(
                "{name} size={} mode={mode} sha256={}",
                b.len(),
                sha256_hex(&b)
            )
        }
        Err(_) => format!("{name} absent"),
    }
}

pub fn run(input: &str, dir: &Path) -> Result<String, String> {
    let _ = fs::remove_dir_all(dir);
    let r = run_in(input, dir);
    let _ = fs::remove_dir_all(dir);
    r
}

fn run_in(input: &str, dir: &Path) -> Result<String, String> {
    let mut out = String::new();
    let mut key = sha256(b"default");
    let mut store: Option<FileStore<TestDrbg>> = None;
    let mut opens = 0u32;
    let mut created = 0u64;
    for (ln, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("#") {
            continue;
        }
        writeln!(out, "> {line}").ok();
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let a = Args::parse(&tokens[1..]);
        let ctx = |e: String| format!("line {}: {e}", ln + 1);
        let need = |s: &mut Option<FileStore<TestDrbg>>| -> Result<(), String> {
            s.as_ref()
                .map(|_| ())
                .ok_or_else(|| ctx("store not open".into()))
        };
        let res: Result<String, StoreError> = match tokens[0] {
            "key" => {
                key = sha256(
                    a.words
                        .first()
                        .ok_or_else(|| ctx("key word".into()))?
                        .as_bytes(),
                );
                Ok(format!("key sha256={}", &ctap2::hex(&key)[..16]))
            }
            "open" => {
                store = None;
                opens += 1;
                // Fresh nonce stream per open: never reuse a nonce under one key.
                let drbg = TestDrbg::new(sha256(format!("nonces-{opens}").as_bytes()));
                match FileStore::open(dir, &key, drbg) {
                    Ok(s) => {
                        let s = match a.num::<usize>("capacity").map_err(ctx)? {
                            Some(n) => s.with_capacity(n),
                            None => s,
                        };
                        let msg = format!("opened count={} counter={}", s.len(), s.counter());
                        store = Some(s);
                        Ok(msg)
                    }
                    Err(e) => Err(e),
                }
            }
            "insert" => {
                need(&mut store)?;
                let word = a.get("id").ok_or_else(|| ctx("id".into()))?;
                created += 1;
                let c = cred(
                    word,
                    a.get("rp").unwrap_or("example.com"),
                    a.flag("rk"),
                    created,
                );
                store
                    .as_mut()
                    .map(|s| s.insert(Arc::new(c)).map(|_| "inserted".to_string()))
                    .unwrap_or(Ok(String::new()))
            }
            "remove" => {
                need(&mut store)?;
                let id = sha256(a.get("id").ok_or_else(|| ctx("id".into()))?.as_bytes());
                store
                    .as_mut()
                    .map(|s| {
                        s.remove(&id).map(|r| {
                            r.map(|c| format!("removed {}", show(&c)))
                                .unwrap_or_else(|| "missing".into())
                        })
                    })
                    .unwrap_or(Ok(String::new()))
            }
            "get" => {
                need(&mut store)?;
                let id = sha256(a.get("id").ok_or_else(|| ctx("id".into()))?.as_bytes());
                store
                    .as_ref()
                    .map(|s| {
                        s.get(&id)
                            .map(|r| r.map(|c| show(&c)).unwrap_or_else(|| "missing".into()))
                    })
                    .unwrap_or(Ok(String::new()))
            }
            "list" => {
                need(&mut store)?;
                let rp = a.get("rp").unwrap_or("example.com");
                store
                    .as_ref()
                    .map(|s| {
                        s.list_rp(rp)
                            .map(|v| {
                                v.iter()
                                    .map(|c| format!("\n    {}", show(c)))
                                    .collect::<String>()
                            })
                            .map(|l| format!("list{l}"))
                    })
                    .unwrap_or(Ok(String::new()))
            }
            "clear" => {
                need(&mut store)?;
                store
                    .as_mut()
                    .map(|s| s.clear().map(|v| format!("cleared {}", v.len())))
                    .unwrap_or(Ok(String::new()))
            }
            "count" => {
                need(&mut store)?;
                Ok(format!(
                    "count={}",
                    store.as_ref().map(|s| s.len()).unwrap_or(0)
                ))
            }
            "counter" => {
                need(&mut store)?;
                store
                    .as_mut()
                    .map(|s| s.next_sign_count().map(|c| format!("counter={c}")))
                    .unwrap_or(Ok(String::new()))
            }
            "files" => {
                let mut names: Vec<String> = fs::read_dir(dir)
                    .map(|rd| {
                        rd.filter_map(|e| {
                            e.ok().map(|e| e.file_name().to_string_lossy().into_owned())
                        })
                        .collect()
                    })
                    .unwrap_or_default();
                names.sort();
                #[cfg(unix)]
                let dmode = {
                    use std::os::unix::fs::PermissionsExt;
                    fs::metadata(dir)
                        .map(|m| format!("{:o}", m.permissions().mode() & 0o777))
                        .unwrap_or_default()
                };
                #[cfg(not(unix))]
                let dmode = String::from("-");
                Ok(format!(
                    "dir mode={dmode}{}",
                    names
                        .iter()
                        .map(|n| format!("\n    {}", file_line(dir, n)))
                        .collect::<String>()
                ))
            }
            "tamper" => {
                let name = a.get("file").ok_or_else(|| ctx("file".into()))?;
                let at: i64 = a.num("at").map_err(ctx)?.ok_or_else(|| ctx("at".into()))?;
                let p = dir.join(name);
                let mut b = fs::read(&p).map_err(|e| ctx(e.to_string()))?;
                let i = if at < 0 {
                    (b.len() as i64 + at) as usize
                } else {
                    at as usize
                };
                *b.get_mut(i)
                    .ok_or_else(|| ctx("offset out of range".into()))? ^= 0x01;
                fs::write(&p, b).map_err(|e| ctx(e.to_string()))?;
                Ok(format!("flipped bit 0 of byte {i}"))
            }
            "write" => {
                let name = a.get("file").ok_or_else(|| ctx("file".into()))?;
                let b = unhex(a.get("hex").unwrap_or("")).map_err(ctx)?;
                match check_environment_secrets(&b) {
                    Ok(()) => fs::write(dir.join(name), &b)
                        .map(|_| format!("wrote {} bytes", b.len()))
                        .map_err(|e| StoreError::Io(e.to_string())),
                    Err(_) => Err(StoreError::Io(ENVIRONMENT_SECRET_REFUSAL.into())),
                }
            }
            "setcounter" => {
                let v: u32 = a
                    .words
                    .first()
                    .ok_or_else(|| ctx("value".into()))?
                    .parse()
                    .map_err(|_| ctx("bad value".into()))?;
                fs::create_dir_all(dir).map_err(|e| ctx(e.to_string()))?;
                fs::write(
                    dir.join(se_fido_store::COUNTER_FILE),
                    se_fido_store::encode_counter(v),
                )
                .map_err(|e| ctx(e.to_string()))?;
                Ok(format!("counter file set to {v}"))
            }
            "absent" => {
                let name = a.get("file").ok_or_else(|| ctx("file".into()))?;
                let text = a.get("text").ok_or_else(|| ctx("text".into()))?;
                let b = fs::read(dir.join(name)).map_err(|e| ctx(e.to_string()))?;
                if b.windows(text.len()).any(|w| w == text.as_bytes()) {
                    return Err(ctx(format!("{text} found in {name}")));
                }
                Ok(format!("{text} not present in {name}"))
            }
            other => return Err(ctx(format!("unknown command {other}"))),
        };
        let kind = match &res {
            Ok(s) if s == "missing" => "Missing",
            Ok(_) => "Ok",
            Err(e) => err_kind(e),
        };
        match &res {
            Ok(s) => writeln!(out, "  {s}").ok(),
            Err(e) => writeln!(out, "  error {kind}: {e}").ok(),
        };
        if matches!(tokens[0], "insert" | "remove" | "clear" | "counter") && kind == "Ok" {
            writeln!(out, "  {}", file_line(dir, se_fido_store::CRED_FILE)).ok();
            writeln!(out, "  {}", file_line(dir, se_fido_store::COUNTER_FILE)).ok();
        }
        let want = a.get("expect").unwrap_or("Ok");
        if want != kind {
            return Err(ctx(format!("expected {want}, got {kind}")));
        }
    }
    Ok(out)
}
