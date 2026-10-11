//! Privacy-safe one-line descriptions of CTAPHID traffic for the device log.
//!
//! Pure and target independent so the fixtures can pin the exact text.
//! Only framing metadata is described: channel, CTAPHID command, byte count,
//! the CTAP2 command byte of a request, the status byte of a response, error
//! and keepalive codes, and the channel handed out by INIT. Payload bytes
//! (credential IDs, public keys, PIN material, clientDataHash, nonces,
//! signatures) are never printed.

use ctap2::cbor::{decode, Value};
use ctap2::{Bytes, Status};
use ctaphid::{Command, ErrorCode, REPORT_SIZE, TYPE_INIT};
use std::fmt::Write;
use std::sync::Arc;

/// Direction of a report relative to the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// Host to device (output report, set-report callback).
    In,
    /// Device to host (input report, HandleReport).
    Out,
}

impl Dir {
    fn as_str(self) -> &'static str {
        match self {
            Dir::In => "in ",
            Dir::Out => "out",
        }
    }
}

/// CTAPHID command name for a raw command byte (init bit cleared).
pub fn hid_cmd_name(raw: u8) -> &'static str {
    match Command::from_u8(raw) {
        Some(Command::Ping) => "PING",
        Some(Command::Msg) => "MSG",
        Some(Command::Lock) => "LOCK",
        Some(Command::Init) => "INIT",
        Some(Command::Wink) => "WINK",
        Some(Command::Cbor) => "CBOR",
        Some(Command::Cancel) => "CANCEL",
        Some(Command::Keepalive) => "KEEPALIVE",
        Some(Command::Error) => "ERROR",
        None => "UNKNOWN",
    }
}

/// authenticator API command name for the first byte of a CBOR request.
pub fn ctap_cmd_name(b: u8) -> &'static str {
    match b {
        0x01 => "MakeCredential",
        0x02 => "GetAssertion",
        0x04 => "GetInfo",
        0x06 => "ClientPIN",
        0x07 => "Reset",
        0x08 => "GetNextAssertion",
        0x09 => "BioEnrollment",
        0x0a => "CredentialManagement",
        0x0b => "Selection",
        0x0c => "LargeBlobs",
        0x0d => "Config",
        0x40 => "BioEnrollmentPreview",
        0x41 => "CredentialManagementPreview",
        _ => "Unknown",
    }
}

/// CTAP2 status byte as `Name(0xNN)`.
pub fn status_text(code: u8) -> String {
    match Status::from_code(code) {
        Some(s) => format!("{s:?}(0x{code:02x})"),
        None => format!("Unknown(0x{code:02x})"),
    }
}

fn error_name(code: u8) -> String {
    match ErrorCode::from_u8(code) {
        Some(e) => format!("{e:?}(0x{code:02x})"),
        None => format!("Unknown(0x{code:02x})"),
    }
}

fn u2f_ins_name(ins: u8) -> &'static str {
    match ins {
        0x01 => "Register",
        0x02 => "Authenticate",
        0x03 => "Version",
        _ => "Unknown",
    }
}

/// One-line description of a single HID report.
pub fn describe_report(dir: Dir, p: &[u8]) -> String {
    let d = dir.as_str();
    if p.len() != REPORT_SIZE {
        return format!("{d} report len={} (expected {REPORT_SIZE})", p.len());
    }
    let cid = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
    if p[4] & TYPE_INIT == 0 {
        return format!("{d} cid={cid:08x} cont seq={}", p[4]);
    }
    let raw = p[4] & !TYPE_INIT;
    let bcnt = u16::from_be_bytes([p[5], p[6]]) as usize;
    let mut s = format!("{d} cid={cid:08x} {} bcnt={bcnt}", hid_cmd_name(raw));
    let first = p[7];
    match (Command::from_u8(raw), dir) {
        (Some(Command::Cbor), Dir::In) if bcnt > 0 => {
            let _ = write!(s, " ctap={}(0x{first:02x})", ctap_cmd_name(first));
        }
        (Some(Command::Cbor), Dir::Out) if bcnt > 0 => {
            let _ = write!(s, " status={}", status_text(first));
        }
        (Some(Command::Init), Dir::Out) if bcnt >= 17 => {
            let new_cid = u32::from_be_bytes([p[15], p[16], p[17], p[18]]);
            let _ = write!(
                s,
                " new_cid={new_cid:08x} proto={} caps=0x{:02x}",
                p[19], p[23]
            );
        }
        (Some(Command::Msg), Dir::In) if bcnt >= 2 => {
            let _ = write!(s, " u2f={}(0x{:02x})", u2f_ins_name(p[8]), p[8]);
        }
        (Some(Command::Error), _) if bcnt > 0 => {
            let _ = write!(s, " code={}", error_name(first));
        }
        (Some(Command::Keepalive), _) if bcnt > 0 => {
            let st = match first {
                1 => "Processing",
                2 => "UpNeeded",
                _ => "Unknown",
            };
            let _ = write!(s, " status={st}({first})");
        }
        _ => {}
    }
    s
}

/// Summary of a finished CBOR or MSG request: request command and the
/// response status. Never includes payload bytes.
pub fn describe_result(cid: u32, cmd: Command, request: &[u8], resp: &[u8]) -> String {
    let mut s = format!("done cid={cid:08x} {}", hid_cmd_name(cmd as u8));
    match cmd {
        Command::Msg => {
            if let Some(&ins) = request.get(1) {
                let _ = write!(s, " u2f={}(0x{ins:02x})", u2f_ins_name(ins));
            }
            if resp.len() >= 2 {
                let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
                let _ = write!(s, " sw=0x{sw:04x}");
            }
        }
        _ => {
            if let Some(&c) = request.first() {
                let _ = write!(s, " ctap={}(0x{c:02x})", ctap_cmd_name(c));
            }
            match resp.first() {
                Some(&st) => {
                    let _ = write!(s, " status={}", status_text(st));
                }
                None => s.push_str(" status=<empty>"),
            }
        }
    }
    let _ = write!(s, " resp_len={}", resp.len());
    s
}

fn uuid(b: &[u8]) -> String {
    if b.len() != 16 {
        return format!("<{} bytes>", b.len());
    }
    let h = ctap2::hex(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn text_list(v: Option<&Value>) -> String {
    let Some(Value::Array(items)) = v else {
        return "-".into();
    };
    let names: Vec<String> = items
        .iter()
        .map(|i| match i {
            Value::Text(t) => t.as_str().to_string(),
            other => format!("{other}"),
        })
        .collect();
    format!("[{}]", names.join(","))
}

/// Summary of an authenticatorGetInfo response (status byte + CBOR map):
/// versions, extensions, AAGUID, options, maxMsgSize, PIN/UV protocols,
/// transports and algorithms. GetInfo carries no user data.
pub fn getinfo_summary(resp: &[u8]) -> String {
    let Some((&st, body)) = resp.split_first() else {
        return "getinfo <empty response>".into();
    };
    if st != 0 {
        return format!("getinfo status={}", status_text(st));
    }
    let info = match decode(&Bytes::new(Arc::from(body))) {
        Ok(v) => v,
        Err(e) => return format!("getinfo undecodable: {e:?}"),
    };
    let aaguid = match info.get(0x03) {
        Some(Value::Bytes(b)) => uuid(b.as_slice()),
        _ => "-".into(),
    };
    let options = match info.get(0x04) {
        Some(Value::Map(m)) => {
            let parts: Vec<String> = m
                .iter()
                .map(|(k, v)| match (k, v) {
                    (Value::Text(k), Value::Bool(b)) => format!("{}={b}", k.as_str()),
                    (k, v) => format!("{k}={v}"),
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        _ => "-".into(),
    };
    let max_msg = match info.get(0x05).map(|v| v.as_int()) {
        Some(Ok(n)) => n.to_string(),
        _ => "-".into(),
    };
    let pin_protocols = match info.get(0x06) {
        Some(Value::Array(a)) => {
            let p: Vec<String> = a.iter().map(|v| format!("{v}")).collect();
            format!("[{}]", p.join(","))
        }
        _ => "-".into(),
    };
    let algs = match info.get(0x0a) {
        Some(Value::Array(a)) => {
            let p: Vec<String> = a
                .iter()
                .map(|e| match e.get_text("alg").map(|v| v.as_int()) {
                    Some(Ok(n)) => n.to_string(),
                    _ => "?".into(),
                })
                .collect();
            format!("[{}]", p.join(","))
        }
        _ => "-".into(),
    };
    format!(
        "getinfo versions={} extensions={} aaguid={aaguid} options={options} \
         maxMsgSize={max_msg} pinUvAuthProtocols={pin_protocols} transports={} algorithms={algs}",
        text_list(info.get(0x01)),
        text_list(info.get(0x02)),
        text_list(info.get(0x09)),
    )
}
