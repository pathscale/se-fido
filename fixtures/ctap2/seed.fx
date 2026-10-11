# A different seed gives different keys; same seed is reproducible (see register_login)
seed other
make rp=example.com user=user1
get allow=$1 want=$1
