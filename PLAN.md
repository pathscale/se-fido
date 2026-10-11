# Plan

## M0 Probe (done)

`se-probe` checks what the Secure Enclave allows an ad-hoc signed binary.
Run on macOS 26.5 (25F71), arm64, policy None, no Touch ID:

| step | result |
| --- | --- |
| SecKeyCreateRandomKey, SE token, permanent=false | OK, 15.8 ms |
| public key export | 65 bytes SEC1 uncompressed |
| SecKeyCreateSignature | OK, 4.8 ms, 71 byte DER, verifies with p256 |
| toid token object blob | 324 bytes |
| reload EmptyDataWithToid | OK 0.4 ms, same public key, sign + ECDH OK |
| reload BlobDataWithToid | OK 0.3 ms, same public key, sign OK |
| reload BlobDataNoToid | returns a different key (public key mismatch); excluded |
| permanent=true, data-protection keychain | FAIL OSStatus -34018 "failed to add key to keychain" |
| legacy keychain | not run (opt-in flag) |
| Touch ID access control | not run (would prompt) |

Key attributes report `perm = true` even for `permanent=false` keys;
reload behaviour above is what matters.

Touch ID check, when wanted: `target/debug/se-probe --touchid` (prompts).

## M1 Protocol core (done)

`ctaphid` framing and `ctap2` commands, canonical CBOR, packed self
attestation, deterministic software backend, fixtures.

## M2 Storage (done)

Encrypted credential index, atomic writes (temp file, fsync, rename, fsync
directory), 0600 files in a 0700 directory, monotonic counter with
checksum, tamper and wrong key detection.

## M3 Secure Enclave backend (done)

`SeBackend` in blob mode, storage key from SE ECDH + HKDF. `fixtures se`
registers, logs in, reopens the store with a re-derived key, logs in again
and resets, all through CTAPHID framing and verified relying-party side.

## M4 Virtual HID device (next)

Primary route, pure Rust, user space:

1. CFDictionary from `transport_mac::properties()`.
2. `IOHIDUserDeviceCreateWithProperties`, serial dispatch queue,
   set-report block built as a `#[repr(C)]` Block_layout in Rust,
   `IOHIDUserDeviceActivate`, replies via
   `IOHIDUserDeviceHandleReportWithTimeStamp`.
3. Verify the declarations in `transport-mac/src/ffi.rs` against the SDK
   header before first call.
4. Needs `com.apple.developer.hid.virtual.device`. Without an Apple grant
   the user relaxes SIP/AMFI themselves; we never do or ask for that.
5. Check with `ioreg` that the device appears with usage page 0xF1D0, then
   a browser registration on a test RP.

Fallback, only if the primary route is blocked: a DriverKit HID dext in
pure Rust that hand-matches the DriverKit C++ ABI (Itanium mangling,
vtables, OSObject/IOService layouts). Fragile and unsupported; open
questions on iig dispatch, dext packaging and signing are in
`crates/transport-mac/DESIGN.md`.

## M5 Presence, UV, packaging

- Touch ID through LocalAuthentication, asynchronous, posted back to the
  device queue; KEEPALIVE every 100 ms while waiting; CANCEL honoured.
- SE keys with a biometry access control as an option.
- launchd agent, start at login.
- Later: CTAP 2.1 (`FIDO_2_1`), credProtect, credential management,
  clientPin if a platform requires it.
