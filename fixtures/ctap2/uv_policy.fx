# Per-mode UV policy: flags and GetInfo stay honest
# --- none: no UV bit even if presence returns verified ---
config uv_policy=none
getinfo
presence approve
make rp=example.com user=u1 flags=UP|AT
# platform asking for UV is unsupported when policy is none
make rp=example.com user=u2 uv expect=UnsupportedOption
get rp=example.com allow=$1 want=$1 flags=UP
# force UV request on get: unsupported
get rp=example.com allow=$1 uv expect=UnsupportedOption

# --- presence: UV bit when presence verifies ---
config uv_policy=presence
make rp=example.com user=p1 uv flags=UP|UV|AT
get rp=example.com allow=$1 uv want=$1 flags=UP|UV
# without asking UV, presence may still verify; UV only if provider verified AND policy allows
presence nouv
make rp=example.com user=p2 flags=UP|AT
get rp=example.com allow=$2 flags=UP

# --- biometry: same flag rules as presence for the soft backend ---
config uv_policy=biometry
presence approve
make rp=example.com user=b1 uv rk flags=UP|UV|AT
get rp=example.com uv want=$1 flags=UP|UV pii=yes
