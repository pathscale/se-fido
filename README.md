# se-fido

A FIDO2 / CTAP 2 authenticator in Rust whose credential keys live in the
macOS Secure Enclave. Goal: browsers on the same Mac see it as a USB
security key through a virtual HID device. That last step is not built yet;
see PLAN.md.

Written from the FIDO CTAP 2.1 and W3C WebAuthn Level 2 specifications.
Pure Rust: Apple APIs are reached through hand-written `extern "C"`
declarations, no C, C++, Objective-C or Swift source and no `-sys` crates.

## Crates

| crate | role |
| --- | --- |
| `ctaphid` | CTAPHID framing: packets, reassembly, channels, INIT, PING, WINK, LOCK, CANCEL, KEEPALIVE, timeouts. `no_std` + alloc. |
| `ctap2` | Authenticator: GetInfo, MakeCredential, GetAssertion, GetNextAssertion, Reset, Selection. Canonical CBOR, COSE ES256, packed self attestation. Software backend for fixtures. `no_std` + alloc. |
| `se-fido-store` | Credential index encrypted with ChaCha20-Poly1305 and an atomic monotonic signature counter, on disk. |
| `backend-se` | Secure Enclave keys via Security.framework, storage key from SE ECDH + HKDF, `se-probe` binary. macOS only. |
| `transport-test` | In-memory CTAPHID host and a relying-party verifier, for end-to-end runs. |
| `transport-mac` | Virtual HID via IOHIDUserDevice (create/activate only with `se-fido-device --run`). See DESIGN.md and DEPLOY.md. |
| `fixtures` | Fixture runner (not published). |

Requests are parsed zero copy: byte and text strings are ranges into the
`Arc<[u8]>` request buffer, and loaded credentials are ranges into the
decrypted store buffer.

## What the authenticator advertises

- versions `FIDO_2_0` and `FIDO_2_1`; extension `credProtect` (accepted/echoed);
  ES256 only; transports `usb`
- options `rk`, `up`, `plat=false`; `uv` only when the default UV policy is
  `presence` or `biometry` (not `none`)
- UV policy per credential (default `presence`): `none` (no SE prompt; UP via
  LocalAuthentication with passcode allowed), `presence` (Touch ID or device
  password on each SE private-key use), `biometry` (Touch ID, current set)
- no `clientPin`: zero-length pinUvAuthParam waits for presence and returns
  `PIN_NOT_SET`; `pinUvAuthProtocols` omitted
- CTAP1: `U2F_VERSION` only over CTAPHID_MSG; REGISTER/AUTHENTICATE return
  SW 0x6d00
- attestation: `packed` self attestation (default) or `none`
- maxMsgSize 7609

## AAGUID

`c7ce4e58-6fd2-4eb8-b193-1d528be838a5`, the constant `ctap2::AAGUID` in
`crates/ctap2/src/lib.rs`. It is our own model identifier, generated once
with `uuidgen` for this project. It is not registered with the FIDO
Metadata Service and identifies no certified product; relying parties that
require MDS attestation will not recognise it. To change it, replace the 16
bytes of that one constant with a fresh UUIDv4 and run
`cargo run -p fixtures -- regen`. Never use another vendor AAGUID.

## Secure Enclave storage

Keys are P-256, created with `kSecAttrTokenIDSecureEnclave` and
`permanent=false`. Access control follows the credential UV policy
(`none` / `presence` / `biometry`). The key token object (`toid`, 324
bytes) is stored as the credential key handle and reloaded with
`SecKeyCreateWithData`. The private key never leaves the Secure Enclave.

The credential index is encrypted with a key from SE ECDH + HKDF (see
`backend_se::storage_key`). Unverified: `toid` reload after rebuild or
re-signing the binary, or from another process.

Keychain storage (`permanent=true`) fails with OSStatus -34018 for
binaries without a keychain-access-group entitlement, so blob mode is the
default.

## Build and check

    cargo build --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --check
    cargo run -p fixtures -- check
    target/debug/se-probe            # SE capability probe, no Touch ID
    cargo run -p fixtures -- se      # end to end on the real SE, no Touch ID
    target/debug/se-fido-device      # dry run only; see DEPLOY.md before --run

There are no unit tests; behaviour is pinned by fixtures with byte-for-byte
expected outputs (`fixtures/README.md`). `se-probe --touchid` creates a key
that needs Touch ID per use and will prompt.

## Not verified

- Whether another process (or the same binary after re-signing) can use a
  stored `toid` blob.
- Behaviour with Touch ID protected keys (`--touchid` not run).
- Browser acceptance of the virtual HID device (needs DEPLOY.md steps;
  Safari via AuthenticationServices is the biggest unknown).
- Whether `amfi_get_out_of_my_way=1` plus `csrutil disable` is sufficient
  on macOS 26 for an ad-hoc binary with the restricted entitlement.

## Licence

MIT, see `LICENSE-MIT`.
