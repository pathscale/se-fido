# Fixtures

Behaviour is proven by fixtures, not unit tests. Each `*.fx` file is an
input script; the runner replays it and writes `*.expected` next to it.
`MANIFEST` lists the sha256 of every input and expected file.

    cargo run -p fixtures -- check   # replay, compare byte for byte, exit 1 on diff
    cargo run -p fixtures -- regen   # rewrite *.expected and MANIFEST
    cargo run -p fixtures -- se      # macOS only: real Secure Enclave run, not compared

Environment: `SE_FIDO_FIXTURES` (fixture dir, default `fixtures/`),
`SE_FIDO_TMPDIR` (scratch dir, default `.fixture-tmp/`, gitignored and
removed after each fixture).

Everything is deterministic: the software backend draws keys from
`TestDrbg` (SHA-256 counter mode over a seed), ECDSA uses RFC 6979, store
nonces come from a per-open DRBG, and the client data hash of a request is
sha256 of its fixture line. Same input, same bytes.

A fixture fails on the first line whose `expect=` does not hold, or whose
response fails verification. Comments start with `#`.

## ctaphid/

Drives `ctaphid::Server` with raw 64-byte reports. Packets are built and
decoded by an independent packetizer in the runner.

- `config timeout=MS max_channels=N`, `time MS`
- `init CID NONCE16HEX`
- `raw HEX [len=N]`: one report, zero padded to 64 (or `len`)
- `send CID CMD LEN`: whole message, payload byte i = i*7+3
- `frag CID CMD LEN i j ..`: feed only packets i, j, .. of that message
- `respond CID HEX`: application answer to a pending CBOR request
- `abort CID`, `poll`, `busy`
- `expect=none|process|cancel|wink|send|error:CODE`

## ctap2/

Drives `ctap2::Authenticator` on `SoftBackend` + `MemoryStore` +
`ScriptedPresence`. Every successful registration and assertion is
verified relying-party side (rpIdHash, flags, COSE key on curve, packed
self attestation, ECDSA signature with p256, counter strictly increasing).

- `seed WORD`, `config attestation=packed|none uv=on|off capacity=N`
- `transport hid`: route every request through CTAPHID packets
- `presence approve|nouv|deny|cancel|timeout|uvfail`, `time MS`
- `check store=N keys=N counter=N presence=N`
- `getinfo`, `next`, `reset`, `selection`, `clientpin`, `raw HEX`
- `make` / `get` arguments: `rp= user= userhex= name= display= algs=
  exclude= allow= rk uv up=false ext ea badopt unknownopt rkopt
  pinparam= pinproto= noparam=K badtype=K`; `_` in names becomes a space;
  `$n` refers to the n-th registered credential
- assertions: `expect=Status` (default Ok), `want=$n`, `flags=UP|UV|AT`,
  `n=N`, `pii=yes|no`

## store/

Drives `FileStore` in a scratch directory with a key derived from a word.

- `key WORD`, `open [capacity=N]`, `insert id= rp= [rk]`, `remove id=`,
  `get id=`, `list rp=`, `clear`, `count`, `counter`, `files`
- `tamper file= at=OFFSET` (flips bit 0, negative counts from the end),
  `write file= hex=`, `setcounter N`, `absent file= text=`
- `expect=Ok|Missing|Full|Corrupt|Io|CounterExhausted`

## transport-mac/

- `descriptor`: decodes the HID report descriptor with an independent
  parser and checks 64-byte input and output reports, no report IDs
- `properties`: the virtual device property set (VID/PID placeholders,
  Transport Virtual, usage page 0xF1D0)
- `blocks`: Apple Block ABI layout sizes and offsets (macOS)
