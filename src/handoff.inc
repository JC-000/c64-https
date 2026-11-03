; =============================================================================
; src/handoff.inc — the HANDOFF=1 mailbox: one REU block that a host
; program (Commodore Desk 64's WEB browser is the first) fills with a
; request before it loads this PRG, and that this PRG fills with the reply
; before it loads the host program back. docs/handoff.md is the prose
; version for the host side; this file is the normative one, and
; tools/test_handoff.py reads its values from here.
;
; REU map (a REU of at least 1 MB is required; the host must check):
;   banks $00-$07  the host's (CD64: its RAM drive R:30, max 512 KB). This
;                  PRG writes banks 0-2 (multiply rows, comb table, cold
;                  bank) and the probe bytes at offset 0 of banks 4..128,
;                  so it saves banks 0-2 to HO_SAVE first and restores
;                  them before it returns, and puts every probe byte back
;                  before anything else runs.
;   banks $08-$0A  HO_SAVE: the copy of banks 0-2 while a request runs.
;   bank  $0B      HO_MBOX: request $0000-$015F, reply $0180-$018F,
;                  response head (status line + headers, raw) at
;                  HO_HDR, up to HO_HDR_MAX bytes.
;   bank  $0C-     HO_BODY: the response body (de-chunked), to the REU's end.
; =============================================================================

HO_MBOX         = $0B0000
HO_SAVE_BANK    = $08           ; banks 0-2 are saved to banks 8-10
HO_SAVE_BANKS   = 3
HO_HDR          = HO_MBOX + $0200
HO_HDR_PAGES    = 16            ; 4 KB of response head
HO_BODY         = $0C0000
HO_MIN_TOP_BANK = $0F           ; reu_top_bank >= $0F: 1 MB or more

; ---- request (host writes, this PRG reads) ----
HO_O_MAGIC      = $00           ; 8 B "C64HTTPS" (ASCII)
HO_O_VERSION    = $08           ; 1 B  = HO_VERSION
HO_O_STATE      = $09           ; 1 B  HO_ST_*
HO_O_RET_DEV    = $0A           ; 1 B  device to load the host from (8-30)
HO_O_RET_NLEN   = $0B           ; 1 B  1..16
HO_O_RET_NAME   = $0C           ; 16 B PETSCII file name of the host PRG
HO_O_PORT       = $1C           ; 2 B  LE, TCP port (443)
HO_O_RET_ENTRY  = $1E           ; 2 B  LE, where to jump after loading it
HO_O_HOST       = $20           ; 64 B ASCII, NUL-terminated, 1..63 chars
HO_O_PATH       = $60           ; 256 B ASCII, NUL-terminated; v1 takes
                                ;  1..HTTPS_PATH_MAX (100) chars
HO_REQ_LEN      = $0160

HO_VERSION      = 1
HO_ST_IDLE      = $00           ; nothing pending (the host clears to this)
HO_ST_REQUEST   = $01           ; host: request written, run me
HO_ST_RUNNING   = $02           ; this PRG: banks 0-2 are in HO_SAVE now
HO_ST_DONE      = $03           ; this PRG: reply written, banks restored

; ---- reply (this PRG writes) ----
HO_O_RESULT     = $0180         ; 1 B  HO_R_*
HO_O_HTTP       = $0181         ; 2 B  LE, HTTP status (0 = none)
HO_O_BODY_LEN   = $0183         ; 3 B  LE, body bytes stored at HO_BODY
HO_O_BODY_TOTAL = $0186         ; 3 B  LE, body bytes received
HO_O_FLAGS      = $0189         ; 1 B  HO_F_*
HO_O_HDR_LEN    = $018A         ; 2 B  LE, bytes stored at HO_HDR
HO_O_NET_ERR    = $018C         ; 1 B  net_last_error
HO_O_TRUST      = $018D         ; 1 B  cert_pin_status (TRUST_STORE / pin)
HO_REPLY_LEN    = $10

; Result: 0 = the whole body arrived. Otherwise the step that failed.
HO_R_OK         = 0
HO_R_BAD_REQ    = 2             ; host/path/port/version not acceptable
HO_R_NO_NET     = 3             ; network init or DHCP failed
HO_R_DNS        = 4
HO_R_TCP        = 5
HO_R_TLS        = 6             ; handshake, certificate, name or pin
HO_R_SEND       = 7
HO_R_RECV       = 8             ; response incomplete
HO_R_TOO_BIG    = 9             ; body larger than the REU region
HO_R_REFUSED    = 10            ; trust policy: not dialled

HO_F_COMPLETE   = $01           ; http_recv_body said complete (C=0)
HO_F_SINK_FULL  = $02           ; the body outgrew the REU
HO_F_HDR_TRUNC  = $04           ; the head outgrew HO_HDR_PAGES
HO_F_HANDSHAKE  = $08           ; server Finished verified, name checked
HO_F_HYBRID     = $10           ; X25519MLKEM768 was negotiated

; Used when the request cannot be read (no REU, < 1 MB, no magic) or names
; no usable return program: Commodore Desk 64's own reload (gui/shell.asm
; retStub: LOAD "CD64",8,1 then JMP $0810).
HO_DEF_DEV      = 8
HO_DEF_ENTRY    = $0810
