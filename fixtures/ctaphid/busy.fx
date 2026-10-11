# CBOR requests surface to the application; the device is busy until it answers
init ffffffff 0102030405060708
init ffffffff 0102030405060708
send 00000001 CBOR 1 expect=process
busy
send 00000002 CBOR 1 expect=error:ChannelBusy
send 00000001 PING 0 expect=error:ChannelBusy
respond 00000001 00 expect=send
busy
send 00000002 CBOR 1 expect=process
respond 00000002 00
# empty CBOR message
send 00000001 CBOR 0 expect=error:InvalidLen
# CANCEL from another channel is ignored, from the busy channel it is reported
send 00000001 CBOR 100 expect=process
send 00000002 CANCEL 0 expect=none
send 00000001 CANCEL 0 expect=cancel
busy
abort 00000001
busy
# multi-packet application reply
send 00000001 CBOR 1 expect=process
respond 00000001 00a1016b68656c6c6f2d776f726c64a1016b68656c6c6f2d776f726c64a1016b68656c6c6f2d776f726c64a1016b68656c6c6f2d776f726c64 expect=send
