# Wrong key and modified ciphertext are detected
key k1
open
insert id=c1 rp=secret-rp.example rk
absent file=credentials.bin text=secret-rp.example
absent file=credentials.bin text=alice@example.com
key k2
open expect=Corrupt
key k1
open
count
tamper file=credentials.bin at=-20
open expect=Corrupt
tamper file=credentials.bin at=-20
open
count
tamper file=credentials.bin at=0
open expect=Corrupt
tamper file=credentials.bin at=0
tamper file=credentials.bin at=5
open expect=Corrupt
write file=credentials.bin hex=01
open expect=Corrupt
