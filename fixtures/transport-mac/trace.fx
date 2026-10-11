# Privacy-safe device log lines. Only framing metadata may appear: no
# payload bytes (credential IDs, keys, PIN, clientDataHash, nonces).

# INIT on the broadcast channel; nonce must not be printed.
in ffffffff860008a1b2c3d4e5f60718
# INIT reply with the allocated channel.
out ffffffff860011a1b2c3d4e5f6071800000001020001000005
# CBOR GetInfo request and reply.
in 0000000190000104
out 0000000190000500a5010203
# MakeCredential request; following bytes are CBOR and must not be printed.
in 0000000190008101a5015820deadbeefdeadbeef
in 0000000100cafebabecafebabe
# Keepalive, error, cancel, PING, WINK, LOCK, unknown command.
out 00000001bb000102
out 00000001bf00010b
in 0000000191000000
in 0000000181000412345678
in 0000000188000000
in 0000000184000105
in 00000001c5000000
# CBOR error status reply and unknown CTAP2 command.
out 000000019000012d
in 000000019000016f
# U2F over MSG: VERSION request.
in 0000000183000700030000000000
# Wrong report sizes: 65 bytes (report ID prefixed) and 8 bytes.
in-raw 0000000001900001040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
in-raw 0000000190000104

# Finished requests: command and status only.
result cbor 00000001 04a1 00a1
result cbor 00000001 01a5015820deadbeef 00a3016470616365
result cbor 00000001 02a2 2e
result cbor 00000001 06a1 01
result cbor 00000001 04 -
result msg 00000001 0003000000 5532465f56329000
result msg 00000001 0001030040 6985

# What GetInfo advertises under each UV policy.
getinfo uv_policy=presence
getinfo uv_policy=biometry
getinfo uv_policy=none
