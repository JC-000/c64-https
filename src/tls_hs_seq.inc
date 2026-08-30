; tls_hs_seq.inc — TLS 1.3 handshake message SEQUENCE gate (issue #152)
;
; The problem
; -----------
; `tls_connect` (src/tls13.s) walks the encrypted half of the handshake with
; four unconditional `jsr tls_recv_encrypted` calls, and each of those returns
; C=0 as soon as ONE handshake message of ANY type has dispatched. Both
; dispatchers used to switch only on the message-type byte, so an attacker who
; completed the (unauthenticated) ClientHello/ServerHello exchange could send
; four EncryptedExtensions messages under the handshake write key and nothing
; else: four dispatches satisfied the four calls, the client derived traffic
; keys, set TLS_STATE_CONNECTED and reported success — having seen no
; Certificate, no CertificateVerify and no server Finished. That also skips the
; server-name validation from issue #135, which is a tail call off
; `x509_extract_pubkey`'s success exit: omit the Certificate and it never runs.
;
; The gate
; --------
; `tls_state` is already written by `tls_connect` immediately before each
; receive (TLS_STATE_ENCRYPTED_EXT / _CERTIFICATE / _CERT_VERIFY / _FINISHED),
; so it IS the "which message is due" marker; it was simply never read by the
; dispatchers (its only three readers select the key epoch). Deriving the
; expected type from it, rather than adding a parallel `tls_hs_expected` byte
; written alongside it, is deliberate:
;
;   * the two can never drift out of step, because there is only one of them;
;   * it costs no bytes in tls13.s, which lands in LOADER — the segment with
;     the least headroom on ip65 (the issue's suggested shape would have added
;     ~20 B of stores there on top of the check itself).
;
; Both dispatch sites expand the SAME macro from this file, so the ip65 arm
; (`.else` branch of tls_recv_encrypted in src/tls13.s) and the UCI streaming
; arm (`df_dispatch` in src/tls_deframe.s) cannot diverge — the identical
; defect lived in both.
;
; Why one exact type per step, and not a set
; ------------------------------------------
; RFC 8446 §4.3.2 allows an optional CertificateRequest between
; EncryptedExtensions and Certificate. This client never sends the
; `post_handshake_auth` extension and cannot produce a client Certificate
; message, so a handshake that contains a CertificateRequest cannot complete
; here whatever we do; it was already refused before this change (the type
; switch fell through to DF_ERR_TYPE). It is now refused one step earlier, with
; DF_ERR_SEQ, and that is the ONLY legal-set member this gate turns away.
; Accepting-and-skipping a CertificateRequest would mean re-entering the
; deframer pump from inside dispatch plus a "seen one already" latch to bound
; a malicious server streaming them forever — real code, in the segment with
; the least room, to keep alive a handshake that dies one message later
; regardless. If client certificates are ever implemented, this is the place
; to widen.
;
; NewSessionTicket is likewise not accepted here: it is a post-handshake
; message and cannot legally appear before the server Finished.

; ---------------------------------------------------------------------------
; The table below is indexed by tls_state with a compile-time bias, and the
; range check that guards it tests only the two ends of the window. Both
; assume TLS_STATE_ENCRYPTED_EXT..TLS_STATE_FINISHED are CONTIGUOUS and that
; TLS_STATE_CONNECTED is the first value above the window (constants.inc).
; Insert a state anywhere in that run and the gate would silently read the
; wrong table entry — a runtime hole opened by an innocuous-looking edit to a
; list of equates. These cost nothing and turn that into a build error.
; ---------------------------------------------------------------------------
.assert TLS_STATE_CERTIFICATE = TLS_STATE_ENCRYPTED_EXT + 1, error, "TLS_HS_SEQ: TLS_STATE_CERTIFICATE must follow TLS_STATE_ENCRYPTED_EXT (tls_hs_allowed is indexed by tls_state)"
.assert TLS_STATE_CERT_VERIFY = TLS_STATE_CERTIFICATE + 1, error, "TLS_HS_SEQ: TLS_STATE_CERT_VERIFY must follow TLS_STATE_CERTIFICATE (tls_hs_allowed is indexed by tls_state)"
.assert TLS_STATE_FINISHED = TLS_STATE_CERT_VERIFY + 1, error, "TLS_HS_SEQ: TLS_STATE_FINISHED must follow TLS_STATE_CERT_VERIFY (tls_hs_allowed is indexed by tls_state)"
.assert TLS_STATE_CONNECTED = TLS_STATE_FINISHED + 1, error, "TLS_HS_SEQ: TLS_STATE_CONNECTED must be the first state above the gated window (the range check uses TLS_STATE_FINISHED+1)"

; ---------------------------------------------------------------------------
; TLS_HS_SEQ_TABLE — the expected message type for each of the four states
; tls_connect passes through, indexed by tls_state. Expand ONCE per object,
; in the same segment as the check that reads it.
; ---------------------------------------------------------------------------
.macro TLS_HS_SEQ_TABLE
tls_hs_allowed:
        .byte   TLS_HS_ENCRYPTED_EXT    ; TLS_STATE_ENCRYPTED_EXT (3)
        .byte   TLS_HS_CERTIFICATE      ; TLS_STATE_CERTIFICATE   (4)
        .byte   TLS_HS_CERT_VERIFY      ; TLS_STATE_CERT_VERIFY   (5)
        .byte   TLS_HS_FINISHED         ; TLS_STATE_FINISHED      (6)
.endmacro

; ---------------------------------------------------------------------------
; TLS_HS_SEQ_CHECK reject_label
;
; In:      A = received handshake message type (preserved)
; Out:     falls through when the message is the one the protocol requires in
;          the current tls_state; branches to `reject_label` otherwise.
; Clobbers X. Flags are not meaningful on the fall-through path (the caller's
; existing type switch re-tests A).
;
; The two range tests are load-bearing, not defensive padding: without them a
; dispatch reached in any other state (IDLE, CONNECTED, ERROR=$FF) would index
; outside the 4-byte table and compare A against whatever code byte happens to
; sit there. Deleting them is NOT caught by simply presenting a message at an
; out-of-window state: the neighbouring bytes are unlikely to equal the type
; under test, so the reject still happens — by code layout rather than by
; logic, and a reordering of this file could silently flip it. The cases in
; tools/test_hs_sequence.py therefore READ the bytes adjacent to
; tls_hs_allowed (the label is exported for exactly this) and use those values
; as the message type, so removing either bound turns the reject into an
; accept and the test fails. Mutation-checked: widening the upper bound, and
; deleting both bounds, are each detected.
; ---------------------------------------------------------------------------
.macro TLS_HS_SEQ_CHECK reject_label
        ldx     tls_state
        cpx     #TLS_STATE_ENCRYPTED_EXT
        bcc     reject_label
        cpx     #TLS_STATE_FINISHED+1
        bcs     reject_label
        cmp     tls_hs_allowed - TLS_STATE_ENCRYPTED_EXT, x
        bne     reject_label
.endmacro
