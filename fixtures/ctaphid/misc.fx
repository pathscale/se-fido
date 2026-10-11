# Unknown and host-forbidden commands, WINK, LOCK, report size
init ffffffff 0102030405060708
raw 00000001d50000 expect=error:InvalidCmd
# MSG (CTAP1) surfaces to the application (U2F); framing accepts it
send 00000001 MSG 1 expect=process
abort 00000001
raw 00000001bb000101 expect=error:InvalidCmd
raw 00000001bf000101 expect=error:InvalidCmd
send 00000001 WINK 0 expect=wink
# LOCK for 2 s excludes other channels
init ffffffff 0102030405060708
raw 0000000184000102 expect=send
send 00000002 PING 0 expect=error:ChannelBusy
send 00000001 PING 0 expect=send
time 2000
send 00000002 PING 0 expect=send
# LOCK 10 then LOCK 0 releases
raw 000000018400010a expect=send
raw 0000000184000100 expect=send
send 00000002 PING 0 expect=send
# LOCK > 10 s or without argument
raw 000000018400010b expect=error:InvalidPar
raw 0000000184000000 expect=error:InvalidPar
# reports that are not 64 bytes are ignored
raw 0000000181 len=63 expect=none
raw 0000000181 len=65 expect=none
