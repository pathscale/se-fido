# Presence outcomes map to CTAP2 status codes and leave no state behind
presence deny
make expect=OperationDenied
selection expect=OperationDenied
reset expect=OperationDenied
presence uvfail
make expect=OperationDenied
presence cancel
make expect=KeepaliveCancel
selection expect=KeepaliveCancel
presence timeout
make expect=UserActionTimeout
check store=0 keys=0 counter=0
presence approve
selection
