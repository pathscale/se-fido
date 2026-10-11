# Continuation packet sequencing and interleaving (CTAP 2.1 11.2.4)
init ffffffff 0102030405060708
init ffffffff 0102030405060708
# PING 200 = packets 0 (init), 1 (seq 0), 2 (seq 1), 3 (seq 2)
# skipping seq 0
frag 00000001 PING 200 0 2 expect=error:InvalidSeq
# the partial message was dropped, so a late continuation is ignored
frag 00000001 PING 200 1 expect=none
# repeated sequence number
frag 00000001 PING 200 0 1 1 expect=error:InvalidSeq
# new init packet on the same channel while continuations are owed
frag 00000001 PING 100 0 expect=none
send 00000001 PING 1 expect=error:InvalidSeq
# another channel during assembly is busy (init and continuation), original completes
frag 00000001 PING 150 0 expect=none
send 00000002 PING 1 expect=error:ChannelBusy
raw 0000000200 expect=error:ChannelBusy
frag 00000001 PING 150 1 2 expect=send
# broadcast INIT is allowed mid message and does not disturb it
frag 00000001 PING 80 0 expect=none
init ffffffff 3132333435363738 expect=send
frag 00000001 PING 80 1 expect=send
# INIT on the same channel mid message resyncs and drops the message
frag 00000001 PING 80 0 expect=none
init 00000001 4142434445464748 expect=send
frag 00000001 PING 80 1 expect=none
# spurious continuation
raw 0000000100010203 expect=none
# CANCEL during assembly discards the partial message
frag 00000001 PING 100 0 expect=none
send 00000001 CANCEL 0 expect=none
frag 00000001 PING 100 1 expect=none
