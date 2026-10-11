# Signature counter file: monotonic, persisted, checksummed
open
counter
counter
counter
open
counter
clear
open
counter
# corrupted counter file
write file=counter hex=6a756e6b
open expect=Corrupt
setcounter 7
tamper file=counter at=-1
open expect=Corrupt
# exhaustion
setcounter 4294967294
open
counter
counter expect=CounterExhausted
open
counter expect=CounterExhausted
