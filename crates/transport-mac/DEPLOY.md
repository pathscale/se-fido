# Deploying the virtual HID device

This turns se-fido into something Chrome and Safari can see as a security
key. It requires a restricted entitlement. Apple does not grant
`com.apple.developer.hid.virtual.device` for ad-hoc local experiments, so
the practical path on a personal Mac is to relax SIP/AMFI yourself, then
ad-hoc codesign the binary with that entitlement.

Uncertainty is marked. macOS 26 may change AMFI behaviour; if a step fails,
stop and record the error rather than disabling more of the system.

## Risk

Disabling SIP and AMFI weakens malware protections for the whole Mac.
Do this only on a machine you accept that risk on, and reverse the
settings when you are done testing. We never run these commands for you.

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

Expected: a line that the virtual HID device activated. Leave it running.

If CreateWithProperties returns null: the entitlement is still being
rejected. Re-check codesign entitlements dump and AMFI/SIP state.

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
3. Presence is auto-approved today (no Touch ID prompt).
4. Repeat in Safari. **Uncertainty:** Safari routes WebAuthn through
   AuthenticationServices; virtual HID keys may be ignored or handled
   differently from Chrome. Record what happens either way.

Optional data dir:

```
SE_FIDO_DIR=/path/to/dir ./target/debug/se-fido-device --run
```

Default is `$HOME/Library/Application Support/se-fido`.

## 7. Stop

Kill the `se-fido-device` process. The device node should disappear from
`hidutil list`.

## 8. Restore security settings

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

## What this does not do

- No DriverKit dext.
- No Touch ID (M5).
- No Apple Developer Program provisioning of the entitlement.
