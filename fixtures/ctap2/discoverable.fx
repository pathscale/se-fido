# Discoverable credentials, numberOfCredentials, GetNextAssertion and its expiry
make rp=example.com user=u1 rk
make rp=example.com user=u2 rk
make rp=other.com user=u3 rk
make rp=example.com user=u4
# newest first; user names withheld without UV
get rp=example.com want=$2 n=2 pii=no
next want=$1
next expect=NotAllowed
# any other command clears the iterator
get rp=example.com want=$2 n=2
getinfo
next expect=NotAllowed
# state expires 30 s after the GetAssertion
time 1000
get rp=example.com want=$2 n=2
time 31001
next expect=NotAllowed
time 32000
get rp=example.com want=$2 n=2
time 62000
next want=$1
next expect=NotAllowed
