# PING echo at every fragmentation boundary (57 bytes init, 59 per continuation)
init ffffffff 0102030405060708
send 00000001 PING 0 expect=send
send 00000001 PING 1 expect=send
send 00000001 PING 56 expect=send
send 00000001 PING 57 expect=send
send 00000001 PING 58 expect=send
send 00000001 PING 115 expect=send
send 00000001 PING 116 expect=send
send 00000001 PING 117 expect=send
send 00000001 PING 1000 expect=send
send 00000001 PING 7608 expect=send
# maximum message: 57 + 128 * 59 = 7609
send 00000001 PING 7609 expect=send
# declared length 7610 is rejected
raw 00000001811dba expect=error:InvalidLen
