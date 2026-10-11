# No clientPin: zero-length pinUvAuthParam is the platform selection probe
make pinparam= expect=PinNotSet
get pinparam= expect=PinNotSet
make pinparam=01010101010101010101010101010101 expect=MissingParameter
make pinparam=01010101010101010101010101010101 pinproto=1 expect=InvalidParameter
check store=0 keys=0
