# Non-discoverable registration and login with allowList
make rp=example.com user=user1 flags=UP|AT
get rp=example.com allow=$1 want=$1 flags=UP
get rp=example.com allow=$1 want=$1 flags=UP
# credential is bound to its RP
get rp=evil.com allow=$1 expect=NoCredentials
# unknown credential id
get rp=example.com allow=00010203 expect=NoCredentials
# no allowList and no discoverable credentials
get rp=example.com expect=NoCredentials
# presence is still collected before NoCredentials (no silent probing)
check store=1 keys=1 presence=6
