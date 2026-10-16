# Deploying the virtual HID device

Durable operation requires both the virtual HID entitlement and an authorized
data-protection Keychain access group. A plist entry alone grants neither.
Use the signing identity and provisioning configuration that authorize these
entitlements. Ad-hoc signing is not a durable Keychain deployment path.

## Build

Build the transport package and its device binary using the workspace's
required build wrapper. Running the binary without `--run` prints a dry run
and does not activate a HID device.

## Sign

Set `SE_FIDO_SIGN_IDENTITY` to the authorized signing identity and
`SE_FIDO_KEYCHAIN_ACCESS_GROUP` to the fully prefixed access group granted to
that identity by its provisioning configuration. Then run:

```
bun crates/transport-mac/scripts/codesign.bun.ts target/debug/se-fido-device
```

The script requires both values, rejects ad-hoc signing, expands the entitlement
template into a private temporary file, signs and verifies the binary, then
removes that file. It does not invent a signing prefix or expand Xcode build
variables. The checked-in plist is a template and must not be passed directly
to `codesign`. Signature verification does not prove that the operating system
grants either entitlement; verify access on the deployment machine.

## Run and verify

Start the signed binary with `--run` only when ready to activate the device.
An optional `SE_FIDO_DIR` selects its data directory. The default is the user's
application support directory. Keychain or entitlement failures are errors;
there is no fallback to disk-backed private-key handles.

Confirm device discovery, credential enrollment, assertion and restart using
a synthetic relying party and an isolated data directory. Exercise the chosen
user-verification policy explicitly. Do not use `--auto-approve` for real use.
Stop the device process after verification. Hardware access and restart
behavior require validation on the deployment machine.
