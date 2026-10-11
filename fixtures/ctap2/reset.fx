# authenticatorReset clears credentials and keys; the counter stays monotonic
make user=u1 rk
make user=u2
check store=2 keys=2 counter=2
reset
check store=0 keys=0 counter=2
get allow=$1 expect=NoCredentials
get expect=NoCredentials
make user=u3
