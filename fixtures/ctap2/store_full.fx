# Credential store limit
config capacity=1
make user=u1
make user=u2 expect=KeyStoreFull
check store=1 keys=1
