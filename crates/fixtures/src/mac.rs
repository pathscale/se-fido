//! transport-mac fixtures: report descriptor, property set, Block ABI layout.

use crate::util::sha256_hex;
use std::fmt::Write;
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
            other => return Err(format!("line {}: unknown command {other}", ln + 1)),
        }
    }
    Ok(out)
}
