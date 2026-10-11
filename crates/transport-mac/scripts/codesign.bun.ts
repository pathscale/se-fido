// Ad-hoc codesign se-fido-device with the virtual HID entitlement.
// Usage: bun crates/transport-mac/scripts/codesign.bun.ts [path-to-binary]
// Default binary: target/debug/se-fido-device

const bin = process.argv[2] ?? "target/debug/se-fido-device";
const ent = "crates/transport-mac/entitlements.plist";
const proc = Bun.spawnSync(["codesign", "--force", "--sign", "-", "--entitlements", ent, bin], {
  stdout: "inherit",
  stderr: "inherit",
});
if (proc.exitCode !== 0) {
  console.error("codesign failed");
  process.exit(proc.exitCode ?? 1);
}
const verify = Bun.spawnSync(["codesign", "-d", "--entitlements", "-", bin], {
  stdout: "inherit",
  stderr: "inherit",
});
process.exit(verify.exitCode ?? 0);
