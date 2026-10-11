//! transport-mac fixtures: the HID report descriptor decoded by an
//! independent short-item parser, and the device property set.
//!
//! Commands: `descriptor`, `properties`.

use crate::util::sha256_hex;
use std::fmt::Write;
use transport_mac::{properties, PropValue, DEFAULT_IDENTITY, REPORT_DESCRIPTOR};

fn item_name(kind: u8, tag: u8) -> &'static str {
    match (kind, tag) {
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
    }
}

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
        writeln!(
            out,
            "  {:indent$}{} 0x{v:x}",
            "",
            item_name(kind, tag),
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
            "properties" => {
                for (k, v) in properties(&DEFAULT_IDENTITY) {
                    let v = match v {
                        PropValue::Number(n) => format!("0x{n:x}"),
                        PropValue::Text(t) => format!("\"{t}\""),
                        PropValue::Data(d) => {
                            format!("data[{}] sha256={}", d.len(), &sha256_hex(d)[..16])
                        }
                    };
                    writeln!(out, "  {k} = {v}").ok();
                }
            }
            other => return Err(format!("line {}: unknown command {other}", ln + 1)),
        }
    }
    Ok(out)
}
