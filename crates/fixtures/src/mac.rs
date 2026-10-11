//! transport-mac fixtures: report descriptor, property set, Block ABI layout,
//! and the privacy-safe trace lines the device writes to its log.
//!
//! Trace commands: `in HEX` / `out HEX` describe one report (HEX is zero
//! padded to 64 bytes), `in-raw HEX` keeps the given length, `result CMD
//! CID REQHEX RESPHEX` describes a finished request, `getinfo
//! uv_policy=none|presence|biometry` summarises a soft authenticator GetInfo.

use crate::util::{sha256_hex, unhex};
use ctap2::soft::{MemoryStore, ScriptedPresence, SoftBackend};
use ctap2::{Authenticator, AuthenticatorConfig, Bytes, TestDrbg, UvPolicy};
use ctaphid::Command;
use std::fmt::Write;
use transport_mac::trace::{describe_report, describe_result, getinfo_summary, Dir};
use transport_mac::{properties_text, DEFAULT_IDENTITY, REPORT_DESCRIPTOR};

#[cfg(target_os = "macos")]
use transport_mac::block::{
    BLOCK_HAS_COPY_DISPOSE, BLOCK_IS_GLOBAL, BLOCK_NEEDS_FREE, DESCRIPTOR_SIZE,
    LITERAL_SIZE_NO_CAPTURE, LITERAL_SIZE_PTR_CAPTURE, OFFSET_CAPTURED, OFFSET_DESCRIPTOR,
    OFFSET_FLAGS, OFFSET_INVOKE, OFFSET_ISA, OFFSET_RESERVED,
};

fn descriptor(out: &mut String) -> Result<(), String> {
    let d = &REPORT_DESCRIPTOR;
    writeln!(out, "  {} bytes sha256={}", d.len(), sha256_hex(d)).ok();
    let (mut i, mut depth, mut in_bits, mut out_bits) = (0usize, 0i32, 0u32, 0u32);
    let (mut size, mut count) = (0u32, 0u32);
    while i < d.len() {
        let p = d[i];
        let n = [0, 1, 2, 4][(p & 3) as usize];
        let (kind, tag) = ((p >> 2) & 3, p >> 4);
        let data = d.get(i + 1..i + 1 + n).ok_or("truncated item")?;
        let v = data.iter().rev().fold(0u32, |acc, b| acc << 8 | *b as u32);
        if kind == 0 && tag == 0xc {
            depth -= 1;
        }
        let name = match (kind, tag) {
            (0, 0x8) => "Input",
            (0, 0x9) => "Output",
            (0, 0xa) => "Collection",
            (0, 0xc) => "End Collection",
            (1, 0x0) => "Usage Page",
            (1, 0x1) => "Logical Minimum",
            (1, 0x2) => "Logical Maximum",
            (1, 0x7) => "Report Size",
            (1, 0x8) => "Report ID",
            (1, 0x9) => "Report Count",
            (2, 0x0) => "Usage",
            _ => "?",
        };
        writeln!(
            out,
            "  {:indent$}{} 0x{v:x}",
            "",
            name,
            indent = depth.max(0) as usize * 2
        )
        .ok();
        match (kind, tag) {
            (0, 0xa) => depth += 1,
            (1, 0x7) => size = v,
            (1, 0x9) => count = v,
            (1, 0x8) => return Err("report IDs not allowed for CTAPHID".into()),
            (0, 0x8) => in_bits += size * count,
            (0, 0x9) => out_bits += size * count,
            _ => {}
        }
        i += 1 + n;
    }
    if depth != 0 {
        return Err("unbalanced collections".into());
    }
    writeln!(
        out,
        "  input report {} bytes, output report {} bytes",
        in_bits / 8,
        out_bits / 8
    )
    .ok();
    if in_bits != 512 || out_bits != 512 {
        return Err("CTAPHID needs 64-byte input and output reports".into());
    }
    Ok(())
}

fn props(out: &mut String) {
    for line in properties_text(&DEFAULT_IDENTITY).lines() {
        writeln!(out, "  {line}").ok();
    }
}

#[cfg(target_os = "macos")]
fn blocks(out: &mut String) {
    writeln!(out, "  literal_no_capture={LITERAL_SIZE_NO_CAPTURE}").ok();
    writeln!(out, "  literal_ptr_capture={LITERAL_SIZE_PTR_CAPTURE}").ok();
    writeln!(out, "  descriptor={DESCRIPTOR_SIZE}").ok();
    writeln!(out, "  offset_isa={OFFSET_ISA}").ok();
    writeln!(out, "  offset_flags={OFFSET_FLAGS}").ok();
    writeln!(out, "  offset_reserved={OFFSET_RESERVED}").ok();
    writeln!(out, "  offset_invoke={OFFSET_INVOKE}").ok();
    writeln!(out, "  offset_descriptor={OFFSET_DESCRIPTOR}").ok();
    writeln!(out, "  offset_captured={OFFSET_CAPTURED}").ok();
    writeln!(out, "  BLOCK_IS_GLOBAL=0x{BLOCK_IS_GLOBAL:x}").ok();
    writeln!(out, "  BLOCK_HAS_COPY_DISPOSE=0x{BLOCK_HAS_COPY_DISPOSE:x}").ok();
    writeln!(out, "  BLOCK_NEEDS_FREE=0x{BLOCK_NEEDS_FREE:x}").ok();
}

fn packet(hex: &str, pad: bool) -> Result<Vec<u8>, String> {
    let mut p = unhex(hex)?;
    if pad {
        if p.len() > 64 {
            return Err("packet longer than 64 bytes".into());
        }
        p.resize(64, 0);
    }
    Ok(p)
}

fn trace(line: &str, out: &mut String) -> Result<(), String> {
    let mut words = line.split_whitespace();
    let verb = words.next().unwrap_or("");
    let rest: Vec<&str> = words.collect();
    let one = |i: usize| {
        rest.get(i)
            .copied()
            .ok_or(format!("{verb}: missing argument"))
    };
    let text = match verb {
        "in" => describe_report(Dir::In, &packet(one(0)?, true)?),
        "out" => describe_report(Dir::Out, &packet(one(0)?, true)?),
        "in-raw" => describe_report(Dir::In, &packet(one(0)?, false)?),
        "result" => {
            let cmd = match one(0)? {
                "cbor" => Command::Cbor,
                "msg" => Command::Msg,
                other => return Err(format!("result: bad command {other}")),
            };
            let cid = u32::from_str_radix(one(1)?, 16).map_err(|e| e.to_string())?;
            let req = unhex(one(2)?)?;
            let resp = if one(3)? == "-" {
                Vec::new()
            } else {
                unhex(one(3)?)?
            };
            describe_result(cid, cmd, &req, &resp)
        }
        "getinfo" => {
            let policy = one(0)?
                .strip_prefix("uv_policy=")
                .and_then(UvPolicy::parse)
                .ok_or("getinfo: need uv_policy=none|presence|biometry")?;
            let cfg = AuthenticatorConfig {
                default_uv_policy: policy,
                ..AuthenticatorConfig::default()
            };
            let mut auth = Authenticator::new(
                SoftBackend::new(TestDrbg::new([7; 32])),
                MemoryStore::new(),
                ScriptedPresence::approve(),
                cfg,
            );
            let resp = auth.process(&Bytes::new(vec![ctap2::command::GET_INFO].into()), 0);
            getinfo_summary(&resp)
        }
        _ => return Err(format!("unknown command {verb}")),
    };
    writeln!(out, "  se-fido: {text}").ok();
    Ok(())
}

pub fn run(input: &str) -> Result<String, String> {
    let mut out = String::new();
    for (ln, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("#") {
            continue;
        }
        writeln!(out, "> {line}").ok();
        match line {
            "descriptor" => descriptor(&mut out).map_err(|e| format!("line {}: {e}", ln + 1))?,
            "properties" => props(&mut out),
            "blocks" => {
                #[cfg(target_os = "macos")]
                blocks(&mut out);
                #[cfg(not(target_os = "macos"))]
                return Err(format!("line {}: blocks requires macOS", ln + 1));
            }
            other => trace(other, &mut out).map_err(|e| format!("line {}: {e}", ln + 1))?,
        }
    }
    Ok(out)
}
