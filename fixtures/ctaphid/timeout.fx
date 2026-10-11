# Continuation timeout (1000 ms default between packets)
init ffffffff 0102030405060708
init ffffffff 0102030405060708
time 1000
frag 00000001 PING 100 0 expect=none
time 2000
poll expect=none
time 2001
poll expect=error:MsgTimeout
frag 00000001 PING 100 1 expect=none
# detected lazily on the next report: timeout error first, then the reply
time 3000
frag 00000001 PING 100 0 expect=none
time 8000
send 00000002 PING 1 expect=send
# slow but steady continuations do not time out
time 9000
frag 00000001 PING 300 0 expect=none
time 9900
frag 00000001 PING 300 1 expect=none
time 10800
frag 00000001 PING 300 2 expect=none
time 11700
frag 00000001 PING 300 3 expect=none
time 12600
frag 00000001 PING 300 4 expect=none
time 13500
frag 00000001 PING 300 5 expect=send
