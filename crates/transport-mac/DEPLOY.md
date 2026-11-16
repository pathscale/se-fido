# Deploying the virtual HID device

This turns se-fido into something Chrome and Safari can see as a security
key. Creating the virtual HID device requires the restricted entitlement
`com.apple.developer.hid.virtual.device`. There are two routes:

1. **Personal Mac (supported, the default).** Ad-hoc codesign the binary with
   that entitlement, then relax SIP and AMFI yourself so the ad-hoc
   entitlement is honoured. Keys use Blob storage: Secure Enclave key blobs
   kept in the data directory, which needs no Keychain entitlement. Data
   directories from earlier builds keep working.
2. **Provisioned Keychain storage (opt-in, not yet a working procedure).**
   Sign with an Apple-authorized identity and Keychain access group and run
   with `--storage=keychain`. See the last section for what is still missing.

Uncertainty is marked. macOS 26 may change AMFI behaviour; if a step fails,
stop and record the error rather than disabling more of the system.

# Route 1: personal Mac (ad-hoc signing, SIP and AMFI relaxed)

Apple does not grant `com.apple.developer.hid.virtual.device` for ad-hoc
local experiments, so the practical path on a personal Mac is to relax
SIP/AMFI yourself, then ad-hoc codesign the binary with that entitlement.

## Risk

Disabling SIP and AMFI weakens malware protections for the whole Mac.
Do this only on a machine you accept that risk on. The owner of the Mac makes
these changes from Recovery; this repository never runs these commands for
you. Section 9 reverses them when you are done testing.

## 1. Build

From the repo root:

```
cargo build -p transport-mac --bin se-fido-device
```

Dry run (safe, no device):

```
./target/debug/se-fido-device
```

## 2. Ad-hoc codesign with the entitlement

Leave `SE_FIDO_SIGN_IDENTITY` unset. The script then ad-hoc signs with
`entitlements.plist`, which holds only the virtual HID entitlement:

```
bun crates/transport-mac/scripts/codesign.bun.ts target/debug/se-fido-device
```

Or by hand:

```
codesign --force --sign - --entitlements crates/transport-mac/entitlements.plist target/debug/se-fido-device
codesign -d --entitlements - target/debug/se-fido-device
```

You should see `com.apple.developer.hid.virtual.device`. Without relaxed
AMFI, launching still fails even though the signature looks fine.

Every build that relinks the binary replaces this signature. Repeat this step
after each `cargo build`.

## 3. Relax SIP and AMFI (you do this)

1. Restart and hold the power button to enter Recovery (Apple silicon).
2. Recovery menu: Utilities -> Terminal.
3. SIP off:

   ```
   csrutil disable
   ```

   Confirm with `csrutil status` after reboot (expect "disabled").

4. AMFI boot-arg so unsigned / ad-hoc entitlements are honoured.
   **Uncertainty:** on recent macOS the usual flag is:

   ```
   nvram boot-args="amfi_get_out_of_my_way=1"
   ```

   Some write-ups also use `amfi_unrestrict_task_for_pid=1` or disable
   library validation only. For a restricted *entitlement* on an ad-hoc
   binary, `amfi_get_out_of_my_way=1` is the commonly cited requirement
   alongside `csrutil disable`. If `--run` still fails with a
   not-privileged / null device after SIP is off, try setting that
   boot-arg from Recovery (nvram may be protected when SIP is on).

5. Reboot into macOS.

## 4. Run the device

```
./target/debug/se-fido-device --run
```

Storage defaults to `--storage=blob`. Do not pass `--storage=keychain` on
this route: an ad-hoc signed binary has no Keychain access group, so Keychain
calls fail (OSStatus -34018) and the device refuses to start.

Expected: a line that the virtual HID device activated. Leave it running.

If CreateWithProperties returns null: the entitlement is still being
rejected. Re-check the codesign entitlements dump and AMFI/SIP state.

## 5. Verify the device node

In another terminal:

```
ioreg -l | grep -i F1D0
hidutil list | grep -i -e F1D0 -e se-fido
```

You want a HID device with PrimaryUsagePage 0xF1D0 and Product "se-fido".

## 6. Browser test

1. Open https://webauthn.io (or another WebAuthn test RP) in Chrome.
2. Register with the authenticator selection leaving the external key
   available. When the browser lists security keys, pick se-fido.
3. Confirm presence at the macOS prompt (password or Touch ID, depending on
   `--uv-policy`).
4. Repeat in Safari. **Uncertainty:** Safari routes WebAuthn through
   AuthenticationServices; virtual HID keys may be ignored or handled
   differently from Chrome. Record what happens either way.

Optional data dir:

```
SE_FIDO_DIR=/path/to/dir ./target/debug/se-fido-device --run
```

Default is `$HOME/Library/Application Support/se-fido`.

## 7. Keeping this route working

- Re-sign after every build (step 2). A freshly linked binary carries no
  entitlement and fails to create the device.
- Keep Blob storage (the default) and keep using the same data directory.
  A directory written by earlier builds (`store-key.handle`,
  `store-peer.pub`, `store/`) loads as is; no re-enrollment is needed.
- Keychain mode refuses a directory holding `store-key.handle`, and Blob mode
  refuses a directory created in Keychain mode. Use a separate data directory
  for each mode.
- The Blob key handles work only with this Mac's Secure Enclave. Copying the
  data directory to another Mac does not move credentials, and deleting
  `store-key.handle` makes the credential index unreadable.
- After a macOS update, check `csrutil status` and `nvram boot-args`. If
  either was reset, repeat step 3. **Uncertainty:** whether an update resets
  them varies by release.
- If `--run` starts failing with a null device, re-check the entitlements
  dump (step 2) and SIP/AMFI state (step 3) before changing anything else.

## 8. Stop

Kill the `se-fido-device` process. The device node should disappear from
`hidutil list`.

## 9. Restore security settings

When you are done testing:

1. Recovery -> Terminal.
2. Clear boot-args:

   ```
   nvram -d boot-args
   ```

3. Re-enable SIP:

   ```
   csrutil enable
   ```

4. Reboot. Check:

   ```
   csrutil status
   nvram boot-args
   ```

   Expect SIP enabled and no `amfi_get_out_of_my_way` boot-arg.

With SIP and AMFI restored, the ad-hoc signed device no longer launches.
Your data directory is untouched and works again once you relax them.

## What this route does not do

- No DriverKit dext.
- No Apple Developer Program provisioning of the entitlement.

## After the device works

1. Probe SE keys that require user presence (will prompt):

   ```
   target/debug/se-probe --touchid
   ```

2. Prefer a UV policy explicitly:

   ```
   ./target/debug/se-fido-device --run --uv-policy=presence
   ./target/debug/se-fido-device --run --uv-policy=none
   ./target/debug/se-fido-device --run --uv-policy=biometry
   ```

3. Never leave `--auto-approve` on for real use.

# Route 2: provisioned Keychain storage (opt-in)

Keychain mode stores credential keys as permanent data-protection Keychain
items instead of key blobs in the data directory. It needs:

- an Apple Developer Program team with Apple's approval for the restricted
  `com.apple.developer.hid.virtual.device` entitlement;
- a provisioning profile that authorizes that entitlement and the
  `keychain-access-groups` value, a fully prefixed `TEAMID.group`;
- that profile embedded in the signed code.

**Current limitation.** macOS honours restricted entitlements only when an
embedded provisioning profile authorizes them. A bare command-line binary
such as `target/debug/se-fido-device` cannot carry an
`embedded.provisionprofile`. It has to be wrapped in an app-like bundle
(`Contents/MacOS/se-fido-device`, `Contents/Info.plist`,
`Contents/embedded.provisionprofile`) and the bundle signed; see Apple
TN3125, "Inside Code Signing: Provisioning Profiles". This repository does
not build that bundle yet. Signing the bare binary as shown below produces a
signature that verifies, but with SIP and AMFI enabled the system refuses to
launch it. Until a bundle wrapper exists, this route is not a working
deployment procedure; use route 1.

## Sign

Set `SE_FIDO_SIGN_IDENTITY` to the authorized signing identity and
`SE_FIDO_KEYCHAIN_ACCESS_GROUP` to the fully prefixed access group that the
provisioning profile grants. Then run the script on the code to sign:

```
bun crates/transport-mac/scripts/codesign.bun.ts <path-to-signed-code>
```

With an identity, the script requires a fully prefixed group and expands
`entitlements-keychain.plist` (virtual HID entitlement plus the access group)
into a private temporary file. It then signs and verifies the code and
removes that file. It does not invent a signing prefix or embed a
provisioning profile. Do not pass the template plist directly to `codesign`.
Signature verification does not prove that the operating system grants
either entitlement; verify access on the deployment machine.

## Run

```
SE_FIDO_DIR=/path/to/keychain-dir <signed-device> --run --storage=keychain
```

Use a new, empty data directory. Keychain mode refuses a Blob data directory
(`store-key.handle`), and there is no migration between modes, so moving
credentials from route 1 means re-enrolling them with each relying party.
The storage key's Keychain tag is bound to the canonical data-directory path;
moving that directory requires migration. Keychain or entitlement failures
are errors; there is no fallback to Blob storage.
