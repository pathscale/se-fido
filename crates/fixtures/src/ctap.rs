//! CTAP2 fixtures on the deterministic software backend.
//!
//! Setup: `seed WORD`, `config attestation=packed|none uv_policy=none|presence|biometry capacity=N`,
//! `transport hid` (route every request through CTAPHID framing),
//! `presence approve|deny|cancel|timeout|uvfail|nouv`, `time MS`,
//! `check store=N keys=N counter=N presence=N`.
//!
//! Requests: `getinfo`, `make ..`, `get ..`, `next`, `reset`, `selection`,
//! `clientpin`, `raw HEX`. See fixtures/README.md for the arguments.
//! Assertions on request lines: `expect=Status` (default Ok), `want=$n`,
//! `flags=UP|UV`, `n=N`, `pii=yes|no`. Every Ok registration and assertion
//! is verified relying-party side with p256; any failure aborts the fixture.

use crate::util::{sha256, unhex, Args};
use ctap2::cbor::{decode, encode, Out, Value};
use ctap2::soft::{MemoryStore, ScriptedPresence, SoftBackend};
use ctap2::{
    AttestationFormat, Authenticator, AuthenticatorConfig, Bytes, Presence, PresenceError, Status,
    TestDrbg,
};
use std::fmt::Write;
use transport_test::{rp, Host};

type Auth = Authenticator<SoftBackend<TestDrbg>, MemoryStore, ScriptedPresence>;

struct Cred {
    id: Vec<u8>,
    public_key: Vec<u8>,
    rp: String,
}

struct St {
    auth: Auth,
    now: u64,
    creds: Vec<Cred>,
    host: Option<Host>,
    seen_presence: usize,
    last_counter: u32,
    last_get: Option<(String, [u8; 32])>,
}

fn build(seed: [u8; 32], cfg: AuthenticatorConfig, capacity: Option<usize>) -> Auth {
    let store = capacity
        .map(MemoryStore::with_capacity_limit)
        .unwrap_or_default();
    Authenticator::new(
        SoftBackend::new(TestDrbg::new(seed)),
        store,
        ScriptedPresence::approve(),
        cfg,
    )
}

fn cred_ref(st: &St, r: &str) -> Result<Vec<u8>, String> {
    match r.strip_prefix("$") {
        Some(n) => {
            let i: usize = n.parse().map_err(|_| format!("bad ref {r}"))?;
            st.creds
                .get(i.wrapping_sub(1))
                .map(|c| c.id.clone())
                .ok_or_else(|| format!("no credential {r}"))
        }
        None => unhex(r),
    }
}

fn list(v: Option<&str>) -> Vec<&str> {
    v.map(|s| s.split(",").filter(|x| !x.is_empty()).collect())
        .unwrap_or_default()
}

fn descriptors(ids: &[Vec<u8>]) -> Out<'_> {
    Out::Array(
        ids.iter()
            .map(|id| {
                Out::Map(vec![
                    (Out::Text("id"), Out::Bytes(id)),
                    (Out::Text("type"), Out::Text("public-key")),
                ])
            })
            .collect(),
    )
}

/// Apply `noparam=` / `badtype=` mutations to a top-level parameter map.
fn mutate<'a>(
    mut entries: Vec<(Out<'a>, Out<'a>)>,
    a: &Args,
) -> Result<Vec<(Out<'a>, Out<'a>)>, String> {
    for k in list(a.get("noparam")) {
        let k: i64 = k.parse().map_err(|_| "bad noparam")?;
        entries.retain(|(key, _)| !matches!(key, Out::Int(i) if *i == k));
    }
    for k in list(a.get("badtype")) {
        let k: i64 = k.parse().map_err(|_| "bad badtype")?;
        for (key, v) in entries.iter_mut() {
            if matches!(key, Out::Int(i) if *i == k) {
                *v = Out::Text("x");
            }
        }
    }
    Ok(entries)
}

fn options<'a>(a: &Args, allow_rk: bool) -> Option<Out<'a>> {
    let mut o = Vec::new();
    if a.flag("rk") && allow_rk || a.flag("rkopt") {
        o.push((Out::Text("rk"), Out::Bool(true)));
    }
    if a.flag("uv") {
        o.push((Out::Text("uv"), Out::Bool(true)));
    }
    if a.get("up") == Some("false") {
        o.push((Out::Text("up"), Out::Bool(false)));
    }
    if a.flag("badopt") {
        o.push((Out::Text("rk"), Out::Int(1)));
    }
    if a.flag("unknownopt") {
        o.push((Out::Text("foo"), Out::Bool(true)));
    }
    (!o.is_empty()).then_some(Out::Map(o))
}

fn make_request(st: &St, a: &Args, cdh: &[u8; 32]) -> Result<Vec<u8>, String> {
    let rp_id = a.get("rp").unwrap_or("example.com");
    let user_id = match a.get("userhex") {
        Some(h) => unhex(h)?,
        None => a.get("user").unwrap_or("alice").as_bytes().to_vec(),
    };
    let name = a
        .get("name")
        .unwrap_or("alice@example.com")
        .replace("_", " ");
    let display = a.get("display").unwrap_or("Alice").replace("_", " ");
    let algs: Vec<i64> = list(Some(a.get("algs").unwrap_or("-7")))
        .iter()
        .map(|x| x.parse().map_err(|_| "bad alg"))
        .collect::<Result<_, _>>()?;
    let exclude: Vec<Vec<u8>> = list(a.get("exclude"))
        .iter()
        .map(|r| cred_ref(st, r))
        .collect::<Result<_, _>>()?;
    let pin = a.get("pinparam").map(unhex).transpose()?;
    let mut e = vec![
        (Out::Int(1), Out::Bytes(cdh)),
        (
            Out::Int(2),
            Out::Map(vec![
                (Out::Text("id"), Out::Text(rp_id)),
                (Out::Text("name"), Out::Text("Example")),
            ]),
        ),
        (
            Out::Int(3),
            Out::Map(vec![
                (Out::Text("id"), Out::Bytes(&user_id)),
                (Out::Text("name"), Out::Text(&name)),
                (Out::Text("displayName"), Out::Text(&display)),
            ]),
        ),
        (
            Out::Int(4),
            Out::Array(
                algs.iter()
                    .map(|alg| {
                        Out::Map(vec![
                            (Out::Text("alg"), Out::Int(*alg)),
                            (Out::Text("type"), Out::Text("public-key")),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    if !exclude.is_empty() {
        e.push((Out::Int(5), descriptors(&exclude)));
    }
    if a.flag("ext") {
        e.push((Out::Int(6), Out::Map(vec![])));
    }
    if let Some(o) = options(a, true) {
        e.push((Out::Int(7), o));
    }
    if let Some(p) = &pin {
        e.push((Out::Int(8), Out::Bytes(p)));
    }
    if let Some(p) = a.num::<i64>("pinproto")? {
        e.push((Out::Int(9), Out::Int(p)));
    }
    if a.flag("ea") {
        e.push((Out::Int(10), Out::Int(1)));
    }
    let mut req = vec![0x01];
    req.extend(encode(&Out::Map(mutate(e, a)?)));
    Ok(req)
}

fn get_request(st: &St, a: &Args, cdh: &[u8; 32]) -> Result<Vec<u8>, String> {
    let rp_id = a.get("rp").unwrap_or("example.com");
    let allow: Vec<Vec<u8>> = list(a.get("allow"))
        .iter()
        .map(|r| cred_ref(st, r))
        .collect::<Result<_, _>>()?;
    let pin = a.get("pinparam").map(unhex).transpose()?;
    let mut e = vec![
        (Out::Int(1), Out::Text(rp_id)),
        (Out::Int(2), Out::Bytes(cdh)),
    ];
    if !allow.is_empty() {
        e.push((Out::Int(3), descriptors(&allow)));
    }
    if a.flag("ext") {
        e.push((Out::Int(4), Out::Map(vec![])));
    }
    if let Some(o) = options(a, false) {
        e.push((Out::Int(5), o));
    }
    if let Some(p) = &pin {
        e.push((Out::Int(6), Out::Bytes(p)));
    }
    if let Some(p) = a.num::<i64>("pinproto")? {
        e.push((Out::Int(7), Out::Int(p)));
    }
    let mut req = vec![0x02];
    req.extend(encode(&Out::Map(mutate(e, a)?)));
    Ok(req)
}

fn status_name(code: u8) -> String {
    Status::from_code(code)
        .map(|s| format!("{s:?}"))
        .unwrap_or_else(|| format!("0x{code:02x}"))
}

fn exec(st: &mut St, out: &mut String, req: &[u8]) -> Result<Vec<u8>, String> {
    let resp = match st.host.as_mut() {
        Some(h) => {
            h.now_ms = st.now;
            let (resp, stats) = h.transact(&mut st.auth, req)?;
            writeln!(
                out,
                "  hid out={} in={} packets",
                stats.out_packets, stats.in_packets
            )
            .ok();
            resp
        }
        None => st.auth.process(&Bytes::from(req.to_vec()), st.now),
    };
    let reqs = &st.auth.presence().requests;
    for r in &reqs[st.seen_presence..] {
        writeln!(
            out,
            "  presence {:?} rp={} uv={}",
            r.kind,
            r.rp_id.as_ref().map(|t| t.as_str()).unwrap_or("-"),
            r.require_uv
        )
        .ok();
    }
    st.seen_presence = reqs.len();
    if resp.is_empty() {
        return Err("empty response".into());
    }
    writeln!(out, "  status {} (0x{:02x})", status_name(resp[0]), resp[0]).ok();
    if resp.len() > 1 {
        let body = decode(&Bytes::copy_from_slice(&resp[1..]))
            .map_err(|e| format!("response is not canonical-decodable CBOR: {e:?}"))?;
        if encode(&to_out(&body)?) != resp[1..] {
            return Err("response CBOR is not in CTAP2 canonical form".into());
        }
        writeln!(out, "  body {body}").ok();
    }
    Ok(resp)
}

/// Rebuild an encoder tree from a decoded value (for the canonical check).
fn to_out(v: &Value) -> Result<Out<'_>, String> {
    Ok(match v {
        Value::Unsigned(n) => Out::Int(i64::try_from(*n).map_err(|_| "integer too large")?),
        Value::Negative(n) => Out::Int(-1 - i64::try_from(*n).map_err(|_| "integer too small")?),
        Value::Bytes(b) => Out::Bytes(b),
        Value::Text(t) => Out::Text(t.as_str()),
        Value::Array(a) => Out::Array(a.iter().map(to_out).collect::<Result<_, _>>()?),
        Value::Map(m) => Out::Map(
            m.iter()
                .map(|(k, v)| Ok((to_out(k)?, to_out(v)?)))
                .collect::<Result<_, String>>()?,
        ),
        Value::Bool(b) => Out::Bool(*b),
        Value::Null => Out::Null,
        Value::Undefined => return Err("undefined in response".into()),
    })
}

fn check_counter(st: &mut St, c: u32) -> Result<(), String> {
    if c <= st.last_counter {
        return Err(format!(
            "signature counter not increasing: {} after {}",
            c, st.last_counter
        ));
    }
    st.last_counter = c;
    Ok(())
}

pub fn run(input: &str) -> Result<String, String> {
    let mut seed = sha256(b"default");
    let mut cfg = AuthenticatorConfig::default();
    let mut capacity = None;
    let mut st = St {
        auth: build(seed, cfg.clone(), capacity),
        now: 0,
        creds: Vec::new(),
        host: None,
        seen_presence: 0,
        last_counter: 0,
        last_get: None,
    };
    let mut out = String::new();
    for (ln, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("#") {
            continue;
        }
        writeln!(out, "> {line}").ok();
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let a = Args::parse(&tokens[1..]);
        let r = step(
            &mut st,
            &mut out,
            &tokens,
            &a,
            line,
            &mut seed,
            &mut cfg,
            &mut capacity,
        );
        r.map_err(|e| format!("line {}: {e}", ln + 1))?;
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn step(
    st: &mut St,
    out: &mut String,
    tokens: &[&str],
    a: &Args,
    line: &str,
    seed: &mut [u8; 32],
    cfg: &mut AuthenticatorConfig,
    capacity: &mut Option<usize>,
) -> Result<(), String> {
    let rebuild =
        |st: &mut St, seed: [u8; 32], cfg: &AuthenticatorConfig, capacity: Option<usize>| {
            st.auth = build(seed, cfg.clone(), capacity);
            st.creds.clear();
            st.seen_presence = 0;
            st.last_counter = 0;
            st.last_get = None;
        };
    let cdh = sha256(line.as_bytes());
    let req: Vec<u8> = match tokens[0] {
        "seed" => {
            *seed = sha256(a.words.first().ok_or("seed word")?.as_bytes());
            rebuild(st, *seed, cfg, *capacity);
            return Ok(());
        }
        "config" => {
            if let Some(v) = a.get("attestation") {
                cfg.attestation = match v {
                    "packed" => AttestationFormat::PackedSelf,
                    "none" => AttestationFormat::None,
                    _ => return Err(format!("bad attestation {v}")),
                };
            }
            if let Some(v) = a.get("uv_policy") {
                cfg.default_uv_policy =
                    ctap2::UvPolicy::parse(v).ok_or_else(|| format!("bad uv_policy {v}"))?;
            }
            // Backward-compatible alias: uv=on -> presence, uv=off -> none.
            if let Some(v) = a.get("uv") {
                cfg.default_uv_policy = match v {
                    "on" => ctap2::UvPolicy::Presence,
                    "off" => ctap2::UvPolicy::None,
                    _ => return Err(format!("bad uv {v}")),
                };
            }
            if let Some(n) = a.num("capacity")? {
                *capacity = Some(n);
            }
            rebuild(st, *seed, cfg, *capacity);
            return Ok(());
        }
        "transport" => {
            let mut h = Host::new();
            let cid = h.connect([1, 2, 3, 4, 5, 6, 7, 8])?;
            writeln!(out, "  hid channel {cid:08x}").ok();
            st.host = Some(h);
            return Ok(());
        }
        "presence" => {
            st.auth.presence_mut().answer = match a.words.first().copied().unwrap_or("") {
                "approve" => Ok(Presence {
                    user_verified: true,
                }),
                "nouv" => Ok(Presence {
                    user_verified: false,
                }),
                "deny" => Err(PresenceError::Denied),
                "cancel" => Err(PresenceError::Cancelled),
                "timeout" => Err(PresenceError::Timeout),
                "uvfail" => Err(PresenceError::UvFailed),
                other => return Err(format!("bad presence {other}")),
            };
            return Ok(());
        }
        "time" => {
            st.now = a.words.first().ok_or("ms")?.parse().map_err(|_| "bad ms")?;
            return Ok(());
        }
        "check" => {
            let actual = [
                ("store", st.auth.store().len()),
                ("keys", st.auth.backend().key_count()),
                ("counter", st.auth.store().counter() as usize),
                ("presence", st.auth.presence().requests.len()),
            ];
            for (k, v) in actual {
                if let Some(want) = a.num::<usize>(k)? {
                    if want != v {
                        return Err(format!("check {k}: expected {want}, got {v}"));
                    }
                    writeln!(out, "  {k}={v}").ok();
                }
            }
            return Ok(());
        }
        "getinfo" => vec![0x04],
        "next" => vec![0x08],
        "reset" => vec![0x07],
        "selection" => vec![0x0b],
        "clientpin" => vec![0x06, 0xa0],
        "u2f" => {
            let apdu = unhex(a.words.first().copied().unwrap_or("00030000000000"))?;
            let resp = ctap2::u2f::process(&apdu);
            writeln!(out, "  u2f {}", ctap2::hex(&resp)).ok();
            let want = a.get("want").unwrap_or("5532465f56329000"); // U2F_V2 + 9000
            if ctap2::hex(&resp) != want {
                return Err(format!("u2f: wanted {want}, got {}", ctap2::hex(&resp)));
            }
            return Ok(());
        }
        "raw" => unhex(a.words.first().copied().unwrap_or(""))?,
        "make" => make_request(st, a, &cdh)?,
        "get" => get_request(st, a, &cdh)?,
        other => return Err(format!("unknown command {other}")),
    };
    let resp = exec(st, out, &req)?;
    let status = status_name(resp[0]);
    let want = a.get("expect").unwrap_or("Ok");
    if status != want {
        return Err(format!("expected {want}, got {status}"));
    }
    if resp[0] != 0 {
        return Ok(());
    }
    match tokens[0] {
        "make" => {
            let rp_id = a.get("rp").unwrap_or("example.com").to_string();
            let reg = rp::verify_registration(&resp[1..], &rp_id, &cdh)
                .map_err(|e| format!("RP rejected registration: {e}"))?;
            if reg.aaguid != cfg.aaguid {
                return Err("AAGUID mismatch".into());
            }
            check_counter(st, reg.counter)?;
            st.creds.push(Cred {
                id: reg.cred_id.clone(),
                public_key: reg.public_key.clone(),
                rp: rp_id,
            });
            writeln!(
                out,
                "  rp registered ${} fmt={} att={} flags={} counter={} aaguid={}",
                st.creds.len(),
                reg.fmt,
                reg.attestation,
                rp::flags_str(reg.flags),
                reg.counter,
                ctap2::hex(&reg.aaguid)
            )
            .ok();
            writeln!(
                out,
                "  rp id={} pubkey={}",
                ctap2::hex(&reg.cred_id),
                ctap2::hex(&reg.public_key)
            )
            .ok();
            assert_flags(a, reg.flags)?;
        }
        "get" | "next" => {
            let (rp_id, cdh) = if tokens[0] == "get" {
                let rp_id = a.get("rp").unwrap_or("example.com").to_string();
                st.last_get = Some((rp_id.clone(), cdh));
                (rp_id, cdh)
            } else {
                st.last_get.clone().ok_or("next without get")?
            };
            let creds = &st.creds;
            let asr = rp::verify_assertion(&resp[1..], &rp_id, &cdh, |id| {
                creds
                    .iter()
                    .find(|c| c.id == id && c.rp == rp_id)
                    .map(|c| c.public_key.clone())
            })
            .map_err(|e| format!("RP rejected assertion: {e}"))?;
            let idx = st
                .creds
                .iter()
                .position(|c| c.id == asr.cred_id)
                .map(|i| i + 1)
                .unwrap_or(0);
            check_counter(st, asr.counter)?;
            writeln!(
                out,
                "  rp assertion ${idx} flags={} counter={} sig=valid user_id={} name={} display={} n={}",
                rp::flags_str(asr.flags),
                asr.counter,
                asr.user_id.as_ref().map(|u| ctap2::hex(u)).unwrap_or_else(|| "-".into()),
                asr.user_name.as_deref().unwrap_or("-"),
                asr.user_display_name.as_deref().unwrap_or("-"),
                asr.number_of_credentials.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
            )
            .ok();
            if let Some(w) = a.get("want") {
                if w != format!("${idx}") {
                    return Err(format!("wanted credential {w}, got ${idx}"));
                }
            }
            if let Some(n) = a.num::<i128>("n")? {
                if asr.number_of_credentials != Some(n) {
                    return Err(format!(
                        "numberOfCredentials: wanted {n}, got {:?}",
                        asr.number_of_credentials
                    ));
                }
            }
            if let Some(p) = a.get("pii") {
                let has = asr.user_name.is_some() || asr.user_display_name.is_some();
                if has != (p == "yes") {
                    return Err(format!("pii={p} but response has user info: {has}"));
                }
            }
            assert_flags(a, asr.flags)?;
        }
        _ => {}
    }
    Ok(())
}

fn assert_flags(a: &Args, flags: u8) -> Result<(), String> {
    if let Some(f) = a.get("flags") {
        let got = rp::flags_str(flags);
        if got != f {
            return Err(format!("flags: wanted {f}, got {got}"));
        }
    }
    Ok(())
}
