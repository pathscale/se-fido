# A new discoverable credential for the same RP and user replaces the old one
make rp=example.com user=u1 rk
make rp=example.com user=u1 rk
check store=1 keys=1
get rp=example.com want=$2
get rp=example.com allow=$1 expect=NoCredentials
