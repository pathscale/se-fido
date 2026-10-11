# excludeList
make rp=example.com user=u1
make rp=example.com user=u2 exclude=$1 expect=CredentialExcluded
# exclusion is per RP
make rp=other.com user=u2 exclude=$1
check store=2 keys=2
