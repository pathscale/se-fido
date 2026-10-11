# The channel table is bounded; the oldest channel is dropped
config max_channels=3
init ffffffff 0102030405060708
init ffffffff 0102030405060708
init ffffffff 0102030405060708
init ffffffff 0102030405060708
send 00000001 PING 0 expect=error:InvalidChannel
send 00000004 PING 0 expect=send
send 00000002 PING 0 expect=send
