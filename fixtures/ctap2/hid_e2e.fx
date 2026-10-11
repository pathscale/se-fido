# End to end through CTAPHID framing: requests and responses span several packets
transport hid
getinfo
make rp=example.com user=u1 rk uv name=nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn display=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
make rp=example.com user=u2 rk exclude=00112233
get rp=example.com n=2 want=$2
next want=$1
get rp=example.com allow=$1,$2 uv want=$1
presence deny
make rp=example.com user=u3 expect=OperationDenied
presence approve
raw 01a1 expect=InvalidCbor
selection
reset
check store=0 keys=0
