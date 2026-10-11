# Insert, persist, reload, remove, clear
open
insert id=c1 rp=a.com rk
insert id=c2 rp=a.com
insert id=c3 rp=b.com rk
open
count
get id=c2
list rp=a.com
list rp=b.com
list rp=c.com
get id=nope expect=Missing
remove id=c1
remove id=c1 expect=Missing
open
count
get id=c1 expect=Missing
clear
open
count
files
