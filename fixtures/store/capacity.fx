# Capacity limit; replacing an existing credential is allowed when full
open capacity=2
insert id=c1 rp=a.com
insert id=c2 rp=a.com
insert id=c3 rp=a.com expect=Full
insert id=c2 rp=a.com rk
open
count
get id=c2
