; src/net/uci/uci_errors.inc — UCI backend error codes
;
; Values stored in net_last_error by the UCI adapter. 0 = OK.
; Kept deliberately small and distinct from any ip65 error values so
; that future multi-backend debugging can tell them apart at a glance.

UCI_ERR_OK             = $00    ; no error
UCI_ERR_NOT_PRESENT    = $81    ; $DF1D did not read back UCI_ID_VALUE ($C9)
UCI_ERR_CMD_FAILED     = $82    ; UCI reported an error bit after PUSH_CMD
UCI_ERR_NO_IP          = $83    ; GET_IPADDR returned all-zero IP
