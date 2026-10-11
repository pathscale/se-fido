//! CTAPHID fixtures.
//!
//! Commands (one per line, `#` comments):
//!   config max_channels=N timeout=MS   recreate the server
//!   time MS                            set the clock
//!   init CID NONCE16                   CTAPHID_INIT packet
//!   raw HEX [len=N]                    raw report, zero padded to 64 (or N) bytes
//!   send CID CMD LEN                   message of LEN pattern bytes, all packets
//!   frag CID CMD LEN I [I ..]          only the listed packets of that message
//!   respond CID HEX                    application reply to CBOR
//!   abort CID | poll | busy
//! CMD is a name (PING, CBOR, ...) or hex byte. Any line may carry
//! `expect=KIND` with KIND none|process|cancel|wink|send|error:CODE; a
//! mismatch fails the fixture.

use crate::util::{parse_u32_hex, sha256_hex, unhex, Args};
use ctaphid::{
    Action, Command, Config, ErrorCode, Packet, Reassembler, Server, CONT_DATA_SIZE,
    INIT_DATA_SIZE, REPORT_SIZE, TYPE_INIT,
};
use std::fmt::Write;

fn cmd_byte(s: &str) -> Result<u8, String> {
    Ok(match s {
        "PING" => 0x01,
        "MSG" => 0x03,
        "LOCK" => 0x04,
        "INIT" => 0x06,
        "WINK" => 0x08,
        "CBOR" => 0x10,
        "CANCEL" => 0x11,
        "KEEPALIVE" => 0x3b,
        "ERROR" => 0x3f,
        h => u8::from_str_radix(h.trim_start_matches("0x"), 16)
            .map_err(|_| format!("bad command {h}"))?,
    })
}

fn cmd_name(b: u8) -> String {
    match Command::from_u8(b) {
        Some(c) => format!("{c:?}").to_uppercase(),
        None => format!("0x{b:02x}"),
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

/// Independent packetizer (does not use ctaphid::fragment). Allows any
/// command byte and declared length.
fn packets(cid: u32, cmd: u8, payload: &[u8]) -> Vec<Packet> {
    let mut out = Vec::new();
    let mut p = [0u8; REPORT_SIZE];
    p[..4].copy_from_slice(&cid.to_be_bytes());
    p[4] = TYPE_INIT | cmd;
    p[5] = (payload.len() >> 8) as u8;
    p[6] = payload.len() as u8;
    let n = payload.len().min(INIT_DATA_SIZE);
    p[7..7 + n].copy_from_slice(&payload[..n]);
    out.push(p);
    let mut seq = 0u8;
    let mut rest = &payload[n..];
    while !rest.is_empty() {
        let n = rest.len().min(CONT_DATA_SIZE);
        let mut c = [0u8; REPORT_SIZE];
        c[..4].copy_from_slice(&cid.to_be_bytes());
        c[4] = seq;
        c[5..5 + n].copy_from_slice(&rest[..n]);
        out.push(c);
        rest = &rest[n..];
        seq = seq.wrapping_add(1);
    }
    out
}

fn describe_packets(out: &mut String, pkts: &[Packet]) -> Result<Vec<String>, String> {
    let mut kinds = Vec::new();
    writeln!(
        out,
        "  send {} packet(s), sha256 {}",
        pkts.len(),
        &sha256_hex(&pkts.concat())[..16]
    )
    .ok();
    if pkts.len() <= 3 {
        for p in pkts {
            writeln!(out, "    pkt {}", ctap2::hex(p)).ok();
        }
    }
    let mut r = Reassembler::default();
    for p in pkts {
        let Some(m) = r
            .push(p)
            .map_err(|e| format!("device sent malformed framing: {e}"))?
        else {
            continue;
        };
        let name = cmd_name(m.cmd);
        let d = &m.payload;
        if m.cmd == Command::Error as u8 && d.len() == 1 {
            let code = ErrorCode::from_u8(d[0])
                .map(|c| format!("{c:?}"))
                .unwrap_or_else(|| format!("0x{:02x}", d[0]));
            writeln!(out, "    msg cid={:08x} ERROR {code}", m.cid).ok();
            kinds.push(format!("error:{code}"));
        } else if m.cmd == Command::Init as u8 && d.len() == 17 {
            writeln!(
                out,
                "    msg cid={:08x} INIT nonce={} new_cid={} version={} device={}.{}.{} caps=0x{:02x}",
                m.cid,
                ctap2::hex(&d[..8]),
                ctap2::hex(&d[8..12]),
                d[12],
                d[13],
                d[14],
                d[15],
                d[16]
            )
            .ok();
            kinds.push("send".into());
        } else {
            let data = if d.len() <= 32 {
                ctap2::hex(d)
            } else {
                format!("sha256:{}", &sha256_hex(d)[..16])
            };
            let ok = if m.cmd == Command::Ping as u8 {
                if **d == *pattern(d.len()) {
                    " (echo ok)"
                } else {
                    " (ECHO MISMATCH)"
                }
            } else {
                ""
            };
            writeln!(
                out,
                "    msg cid={:08x} {name} len={} data={data}{ok}",
                m.cid,
                d.len()
            )
            .ok();
            kinds.push("send".into());
        }
    }
    Ok(kinds)
}

fn describe(out: &mut String, a: Action) -> Result<String, String> {
    Ok(match a {
        Action::None => {
            writeln!(out, "  none").ok();
            "none".into()
        }
        Action::Send(p) => {
            let kinds = describe_packets(out, &p)?;
            if kinds.len() == 1 {
                kinds[0].clone()
            } else {
                "send".into()
            }
        }
        Action::Wink(p) => {
            writeln!(out, "  wink").ok();
            describe_packets(out, &p)?;
            "wink".into()
        }
        Action::Cancel { cid } => {
            writeln!(out, "  cancel cid={cid:08x}").ok();
            "cancel".into()
        }
        Action::Process { cid, cmd, payload } => {
            let data = if payload.len() <= 32 {
                ctap2::hex(&payload)
            } else {
                format!("sha256:{}", &sha256_hex(&payload)[..16])
            };
            let ok = if *payload == *pattern(payload.len()) {
                " (pattern ok)"
            } else {
                ""
            };
            writeln!(
                out,
                "  process cid={cid:08x} cmd={cmd:?} len={} data={data}{ok}",
                payload.len()
            )
            .ok();
            "process".into()
        }
    })
}

pub fn run(input: &str) -> Result<String, String> {
    let mut s = Server::new(Config::default());
    let mut now = 0u64;
    let mut out = String::new();
    for (ln, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("#") {
            continue;
        }
        writeln!(out, "> {line}").ok();
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let a = Args::parse(&tokens[1..]);
        let ctx = |e: String| format!("line {}: {e}", ln + 1);
        let kind = match tokens[0] {
            "config" => {
                let mut c = Config::default();
                if let Some(n) = a.num("max_channels").map_err(ctx)? {
                    c.max_channels = n;
                }
                if let Some(n) = a.num("timeout").map_err(ctx)? {
                    c.continuation_timeout_ms = n;
                }
                s = Server::new(c);
                None
            }
            "time" => {
                now = a
                    .words
                    .first()
                    .ok_or_else(|| ctx("time needs ms".into()))?
                    .parse()
                    .map_err(|_| ctx("bad ms".into()))?;
                None
            }
            "init" => {
                let cid = parse_u32_hex(a.words.first().ok_or_else(|| ctx("cid".into()))?)
                    .map_err(ctx)?;
                let nonce =
                    unhex(a.words.get(1).ok_or_else(|| ctx("nonce".into()))?).map_err(ctx)?;
                let p = packets(cid, Command::Init as u8, &nonce);
                Some(describe(&mut out, s.handle_report(&p[0], now))?)
            }
            "raw" => {
                let mut b =
                    unhex(a.words.first().ok_or_else(|| ctx("hex".into()))?).map_err(ctx)?;
                let len = a.num::<usize>("len").map_err(ctx)?.unwrap_or(REPORT_SIZE);
                b.resize(len, 0);
                Some(describe(&mut out, s.handle_report(&b, now))?)
            }
            "send" | "frag" => {
                let cid = parse_u32_hex(a.words.first().ok_or_else(|| ctx("cid".into()))?)
                    .map_err(ctx)?;
                let cmd =
                    cmd_byte(a.words.get(1).ok_or_else(|| ctx("cmd".into()))?).map_err(ctx)?;
                let len: usize = a
                    .words
                    .get(2)
                    .ok_or_else(|| ctx("len".into()))?
                    .parse()
                    .map_err(|_| ctx("bad len".into()))?;
                let pkts = packets(cid, cmd, &pattern(len));
                let picks: Vec<usize> = if tokens[0] == "send" {
                    (0..pkts.len()).collect()
                } else {
                    a.words[3..]
                        .iter()
                        .map(|i| i.parse().map_err(|_| ctx(format!("bad index {i}"))))
                        .collect::<Result<_, _>>()?
                };
                writeln!(
                    out,
                    "  ({} packets in message, feeding {})",
                    pkts.len(),
                    picks.len()
                )
                .ok();
                let mut last = None;
                for (k, i) in picks.iter().enumerate() {
                    let p = pkts.get(*i).ok_or_else(|| ctx(format!("no packet {i}")))?;
                    let action = s.handle_report(p, now);
                    let final_one = k + 1 == picks.len();
                    if final_one || action != Action::None {
                        if !final_one {
                            writeln!(out, "  [packet {i}]").ok();
                        }
                        last = Some(describe(&mut out, action)?);
                    }
                }
                last
            }
            "respond" => {
                let cid = parse_u32_hex(a.words.first().ok_or_else(|| ctx("cid".into()))?)
                    .map_err(ctx)?;
                let payload = unhex(a.words.get(1).copied().unwrap_or("")).map_err(ctx)?;
                let p = s
                    .response(cid, Command::Cbor, &payload)
                    .map_err(|e| ctx(e.to_string()))?;
                Some(describe(&mut out, Action::Send(p))?)
            }
            "abort" => {
                let cid = parse_u32_hex(a.words.first().ok_or_else(|| ctx("cid".into()))?)
                    .map_err(ctx)?;
                s.abort(cid);
                None
            }
            "poll" => {
                let p = s.poll(now);
                Some(if p.is_empty() {
                    describe(&mut out, Action::None)?
                } else {
                    describe(&mut out, Action::Send(p))?
                })
            }
            "busy" => {
                writeln!(
                    out,
                    "  busy={}",
                    s.busy_channel()
                        .map(|c| format!("{c:08x}"))
                        .unwrap_or_else(|| "none".into())
                )
                .ok();
                None
            }
            other => return Err(ctx(format!("unknown command {other}"))),
        };
        if let Some(want) = a.get("expect") {
            let got = kind.unwrap_or_else(|| "none".into());
            if got != want {
                return Err(ctx(format!("expected {want}, got {got}")));
            }
        }
    }
    Ok(out)
}
