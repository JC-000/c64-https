; The LOADER_OVERFLOW segment. Under TRUST_STORE it is LOADER_OVERFLOW_TS,
; so the comb cold cfg can move it into CRYPTO_HOT (the trust hook needs
; its NET_CODE room) without moving it for images with no trust store.
.ifdef TRUST_STORE
        .segment "LOADER_OVERFLOW_TS"
.else
        .segment "LOADER_OVERFLOW"
.endif
