// Codesign se-fido-device.
// Usage: bun crates/transport-mac/scripts/codesign.bun.ts [path-to-binary]
// Default binary: target/debug/se-fido-device
//
// Without SE_FIDO_SIGN_IDENTITY (or with "-"): ad-hoc sign with the virtual HID
// entitlement only (entitlements.plist). This is the personal-Mac route; it
// needs SIP and AMFI relaxed and Blob storage. See DEPLOY.md.
// With SE_FIDO_SIGN_IDENTITY and SE_FIDO_KEYCHAIN_ACCESS_GROUP: sign with that
// identity using entitlements-keychain.plist with the access group filled in.
// Restricted entitlements also need an embedded provisioning profile.
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const bin = process.argv[2] ?? "target/debug/se-fido-device";
const identity = process.env.SE_FIDO_SIGN_IDENTITY;
const group = process.env.SE_FIDO_KEYCHAIN_ACCESS_GROUP;

function spawn(args: string[]): number {
  const proc = Bun.spawnSync(args, { stdout: "inherit", stderr: "inherit" });
  return proc.exitCode ?? 1;
}

if (!identity || identity === "-") {
  if (group) {
    console.error("SE_FIDO_KEYCHAIN_ACCESS_GROUP is ignored for ad-hoc signing; run the device with Blob storage");
  }
  const ent = join(import.meta.dir, "..", "entitlements.plist");
  const signed = spawn(["codesign", "--force", "--sign", "-", "--entitlements", ent, bin]);
  if (signed !== 0) {
    console.error("codesign failed");
    process.exit(signed);
  }
  process.exit(spawn(["codesign", "-d", "--entitlements", "-", bin]));
}

if (!group || !/^[A-Z0-9]{10}\.[A-Za-z0-9][A-Za-z0-9.-]*$/.test(group)) {
  console.error("signing with SE_FIDO_SIGN_IDENTITY requires a fully prefixed SE_FIDO_KEYCHAIN_ACCESS_GROUP");
  process.exit(2);
}
const template = await readFile(join(import.meta.dir, "..", "entitlements-keychain.plist"), "utf8");
if (template.split("__KEYCHAIN_ACCESS_GROUP__").length !== 2) {
  throw new Error("invalid Keychain entitlement template");
}
const directory = await mkdtemp(join(tmpdir(), "device-signing-"));
try {
  const entitlements = join(directory, "entitlements.plist");
  await writeFile(entitlements, template.replace("__KEYCHAIN_ACCESS_GROUP__", group), { mode: 0o600 });
  const signed = spawn(["codesign", "--force", "--sign", identity, "--entitlements", entitlements, bin]);
  process.exitCode = signed !== 0 ? signed : spawn(["codesign", "--verify", "--strict", bin]);
} finally {
  await rm(directory, { recursive: true, force: true });
}
console.error("note: restricted entitlements are honoured only with an embedded provisioning profile; see DEPLOY.md");
