# User verification and silent assertions
make rp=example.com user=u1 rk uv flags=UP|UV|AT
get rp=example.com uv flags=UP|UV pii=yes
# up=false: silent, no presence request
get rp=example.com up=false allow=$1 flags=-
check presence=2
# platform asked for UV but the user only showed presence
presence nouv
make rp=example.com user=u2 uv expect=OperationDenied
check store=1
# without built-in UV the uv option is rejected
config uv=off
make rp=example.com user=u1 uv expect=UnsupportedOption
get rp=example.com uv expect=UnsupportedOption
make rp=example.com user=u1 flags=UP|AT
