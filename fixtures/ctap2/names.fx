# user.name is truncated to 64 bytes on a UTF-8 boundary, returned only after UV
make user=u1 rk name=éééééééééééééééééééééééééééééééééééééééé display=Alice_Example
get uv pii=yes
get pii=no
