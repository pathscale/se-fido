# authenticatorGetInfo with and without UV (policy)
getinfo
# parameters after the command byte are ignored
raw 04a0
config uv_policy=none
getinfo
config uv_policy=biometry
getinfo
