# Parameter, type and CBOR errors
make algs=-8 expect=UnsupportedAlgorithm
make algs=-257,-8 expect=UnsupportedAlgorithm
make algs=-257,-7
make noparam=1 expect=MissingParameter
make noparam=2 expect=MissingParameter
make noparam=3 expect=MissingParameter
make noparam=4 expect=MissingParameter
make badtype=1 expect=CborUnexpectedType
make badtype=2 expect=CborUnexpectedType
make badtype=4 expect=CborUnexpectedType
get noparam=1 expect=MissingParameter
get noparam=2 expect=MissingParameter
get badtype=2 expect=CborUnexpectedType
# raw CBOR edge cases
raw 01 expect=MissingParameter
raw 0101 expect=CborUnexpectedType
raw 01a1 expect=InvalidCbor
raw 01a0 expect=MissingParameter
raw 01a0a0 expect=InvalidCbor
raw 01bf01ff expect=InvalidCbor
raw 01a201010102 expect=InvalidCbor
raw 01a101c000 expect=InvalidCbor
raw 01a101fa00000000 expect=InvalidCbor
raw 01a101818181818181818181818181818181818100 expect=InvalidCbor
raw 01a1015bffffffffffffffff expect=InvalidCbor
raw expect=InvalidLength
raw 40 expect=InvalidCommand
clientpin expect=InvalidCommand
# user.id is at most 64 bytes
make userhex=ababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab expect=InvalidLength
make userhex=abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab
# options
make up=false expect=InvalidOption
make badopt expect=CborUnexpectedType
make unknownopt
get rkopt expect=UnsupportedOption
# enterpriseAttestation is not supported
make ea expect=InvalidParameter
# extensions are ignored
make ext
get allow=$3 ext want=$3
