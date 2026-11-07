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
| `se-fido-ctaphid` (lib `ctaphid`) | CTAPHID framing: packets, reassembly, channels, INIT, PING, WINK, LOCK, CANCEL, KEEPALIVE, timeouts. `no_std` + alloc. |
| `se-fido-ctap2` (lib `ctap2`) | Authenticator: GetInfo, MakeCredential, GetAssertion, GetNextAssertion, Reset, Selection. Canonical CBOR, COSE ES256, packed self attestation. Software backend for fixtures. `no_std` + alloc. |
| `se-fido-store` | Credential index encrypted with ChaCha20-Poly1305 and an atomic monotonic signature counter, on disk. |
| `se-fido-backend-se` (lib `backend_se`) | Secure Enclave keys via Security.framework, storage key from SE ECDH + HKDF, `se-probe` binary. macOS only. |
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

Credential keys are permanent data-protection Keychain items backed by the
Secure Enclave. Each encrypted credential index record stores a non-secret
application-tag reference to its keychain item, rather than a private-key
secret or Secure Enclave token object blob. The index is encrypted with
ChaCha20-Poly1305 using a key derived from Secure Enclave ECDH and HKDF.
The storage key's Keychain tag is bound to the canonical data-directory path;
moving that directory requires explicit migration. Only the peer public key
is saved as `store-peer.pub`; the derived key stays in memory.
If Keychain creation or access fails, startup and credential operations return
an error; there is no plaintext secret fallback.

The `se-probe` capability probe uses non-permanent Blob keys in memory only.
Durable authenticators use permanent Keychain keys. Legacy credential
directories containing Blob handles are not migrated automatically. They
require an explicit migration or credential re-enrollment.

The entitlement template requires an explicitly supplied, fully prefixed
Keychain access group. The signing script requires an authorized identity and
expands the template; see [deployment](crates/transport-mac/DEPLOY.md). Its group
must match the access authorized by the signing identity and provisioning
profile. A plist entry alone does not grant Keychain access. Missing entitlement
or unavailable Keychain storage is a hard error.

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
