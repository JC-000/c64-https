; src/trust_policy.inc — the trust policy's modes and verdicts (#155 phase 2, L3)
;
; Shared by the resident hook (src/cert_pin.s, which runs inside the
; handshake) and the no-connection halves (src/net/uci/trust_policy.s,
; src/net/uci/trust_bundle.s). tools/test_trust_policy_6502.py reads the
; values from here.
;
; tp_mode — what the hook enforces on THIS connection. trust_pre sets it
; before the dial; trust_post clears it after the close. Zero, the BSS
; value, refuses: a connection the policy never prepared gets no Finished.

TP_M_NONE       = 0             ; trust_pre did not run: refuse
TP_M_STORE      = 1             ; the store holds the host: enforce ts_rec
TP_M_FIRST      = 2             ; first use: accept, record after close
TP_M_UNPINNED   = 4             ; operator override: accept, never record
TP_M_PIN        = 5             ; build pin, typed host == HTTPS_HOST

; cert_pin_status under TRUST_STORE — the hook's verdict. Positive values
; let the client Finished go out (cert_pin_require); zero and negative
; ones refuse it.
TP_ST_NONE      = $00           ; the hook has not run this connection
TP_ST_MATCH     = $01           ; store or build pin matched
TP_ST_FIRST     = $02           ; first use (= TP_M_FIRST)
TP_ST_ACCEPT    = $03           ; mismatch, but the exact armed hash
TP_ST_UNPINNED  = $04           ; override (= TP_M_UNPINNED)
TP_ST_PINWARN   = $05           ; build pin mismatch, HTTPS_PIN_WARN=1
TP_ST_CHANGED   = $80           ; store mismatch: the accept flow may run
TP_ST_REFUSED   = $81           ; anything else refused (no accept flow)

.assert TP_ST_FIRST = TP_M_FIRST .and TP_ST_UNPINNED = TP_M_UNPINNED, error, "the hook stores those modes as their verdicts"

TP_HASH_LEN     = 32            ; SPKI SHA-256
