# CTAPHID_INIT channel allocation and channel validation (CTAP 2.1 11.2.9.1.3)
init ffffffff 0102030405060708 expect=send
init ffffffff 1112131415161718 expect=send
# INIT on an allocated channel resynchronises and keeps the CID
init 00000001 2122232425262728 expect=send
# INIT payload must be exactly 8 bytes
raw ffffffff86000701020304050607 expect=error:InvalidLen
# INIT on a channel that was never allocated
init 00001234 0000000000000000 expect=error:InvalidChannel
# CID 0 is reserved
raw 00000000810000 expect=error:InvalidChannel
# the broadcast channel only accepts INIT
raw ffffffff810000 expect=error:InvalidChannel
# request on an unallocated channel
raw deadbeef90000104 expect=error:InvalidChannel
