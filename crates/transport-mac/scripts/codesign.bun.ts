// Sign with an explicitly authorized identity and Keychain access group.
// Usage: bun crates/transport-mac/scripts/codesign.bun.ts [path-to-binary]
// Supply SE_FIDO_SIGN_IDENTITY and SE_FIDO_KEYCHAIN_ACCESS_GROUP.
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const identity = process.env.SE_FIDO_SIGN_IDENTITY;
const group = process.env.SE_FIDO_KEYCHAIN_ACCESS_GROUP;
if (!identity || identity === "-" || !group || !/^[A-Z0-9]{10}\.[A-Za-z0-9][A-Za-z0-9.-]*$/.test(group)) {
  console.error("signing requires SE_FIDO_SIGN_IDENTITY and a fully prefixed SE_FIDO_KEYCHAIN_ACCESS_GROUP");
  process.exit(2);
}

const bin = process.argv[2] ?? "target/debug/se-fido-device";
const template = await readFile(new URL("../entitlements.plist", import.meta.url), "utf8");
if (template.split("__KEYCHAIN_ACCESS_GROUP__").length !== 2) {
  throw new Error("invalid Keychain entitlement template");
}
const directory = await mkdtemp(join(tmpdir(), "device-signing-"));
try {
  const entitlements = join(directory, "entitlements.plist");
  await writeFile(entitlements, template.replace("__KEYCHAIN_ACCESS_GROUP__", group), { mode: 0o600 });
  const signed = Bun.spawnSync(["codesign", "--force", "--sign", identity, "--entitlements", entitlements, bin], {
    stdout: "inherit", stderr: "inherit",
  });
  if (signed.exitCode !== 0) process.exitCode = signed.exitCode ?? 1;
  else {
    const verified = Bun.spawnSync(["codesign", "--verify", "--strict", bin], {
      stdout: "inherit", stderr: "inherit",
    });
    process.exitCode = verified.exitCode ?? 1;
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
