; src/net/uci/cold_bank.s — the comb cold-code bank (#155 phase 2, L5)
;
; Code that runs only while no connection is open is kept in the REU, not
; in RAM, and fetched into cert_buf for each call. cert_buf is dead outside
; a handshake, so it doubles as the slot. Linked only under COLD_BANK
; (the uci-comb default; COLD_BANK=0 links the tenants resident again).
;
; Tenants come in groups (src/cold_bank.inc), each LINKED to run in
; cert_buf (cfg/c64-https-uci-onchip-cold.cfg: load = COLD_IMAGE, run =
; COLD_RUN_<group>), never copied there after a link:
;   COLD_G_UI     TARGET_PROMPT_CODE  https_target_prompt (src/boot.s)
;                 COLD_TAIL_UI        its marker byte
;                 TRUST_BUNDLE_CODE   trust_bundle (src/net/uci/trust_bundle.s,
;                                     TRUST_BUNDLE=1): no DOS, so it rides here
;   COLD_G_TRUST  TRUST_STORE_CODE    trust_store_load/_stage/_save
;                 TRUST_POLICY_CODE   trust_pre/_post (src/net/uci/trust_policy.s),
;                                     which call the store directly
;                 COLD_TAIL_TRUST     its marker byte     (TRUST_STORE=1)
; Their state that outlives a call stays resident (TRUST_STORE_BSS); what
; is in an image itself is either constant or written before it is read
; in the same call, because every call runs a fresh copy.
;
; Boot (cold_bank_init) stashes the PRG's COLD_IMAGE into the REU at
; COLD_REU in one DMA and keeps each group's XOR, once per LOAD and only if
; every group's marker arrived; cold_call refuses until it has. A tenant's public name is
; a resident stub, `ldy #COLD_E_x / jmp cold_call`, so callers are
; unchanged. cold_call:
;   1. refuses unless no connection is open: net_tcp_state is CLOSED or
;      CONNECT_FAIL (CONNECTED and ERROR may still hold a socket) AND
;      tls_state is IDLE or ERROR (a session from ClientHello to tls_close
;      owns cert_buf, and a peer EOF leaves the socket CLOSED under it);
;   2. clears cert_buf's copy of the group's marker, fetches the group, and
;      runs it only if the DMA did not time out (reu_dma_timeout, which is
;      sticky: one expired confirm anywhere and the bank stays shut until
;      the next boot), the marker came back, and the group's XOR matches
;      the one boot took from the PRG's copy;
;   3. enters the tenant with the caller's A/X; the tenant returns
;      straight to the caller, so its C/A/X are the call's result.
; A refusal returns C=1 without jumping and sets cold_err (COLD_R_*).
; Under TRUST_STORE it also leaves the store FAILED (ts_state = FAIL,
; ts_reason = cold_err, nothing found or staged): a lookup after a load
; that never ran must not read as "first use".
;
; Call sites, all outside a connection: do_https_get calls
; https_target_prompt, trust_pre and trust_bundle before net_dns_resolve and
; net_tcp_connect, and trust_post after net_tcp_close. A tenant never calls
; another group: the policy reaches the store inside its own group.
;
; Clobbers A, X, Y and the caller-saved state of the tenant it runs.

.include "constants.inc"
.include "net_states.inc"
.include "net_tuning.inc"       ; CERT_BUF_SIZE
.include "cold_bank.inc"

.import reu_execute, reu_dma_timeout
.import net_tcp_state, tls_state, cert_buf
.import cold_target_prompt
.import __COLD_IMAGE_START__, __COLD_IMAGE_SIZE__
.import __COLD_RUN_UI_START__, __TARGET_PROMPT_CODE_LOAD__, __COLD_TAIL_UI_LOAD__

.export cold_call, cold_bank_init, cold_err, cold_g_sum, cold_stashed
.export cold_marker_ui

.ifdef TRUST_STORE
.include "trust_store.inc"
.import cold_ts_load, cold_ts_stage, cold_ts_save
.import cold_tp_pre, cold_tp_post
.ifdef TRUST_BUNDLE
.import cold_tb_check
.endif
.import ts_state, ts_reason, ts_found, ts_staged
.import __COLD_RUN_TRUST_START__, __TRUST_STORE_CODE_LOAD__, __COLD_TAIL_TRUST_LOAD__
.export cold_marker_trust
COLD_R_BUSY  = TS_R_BUSY        ; the store's own codes, so ts_reason can
COLD_R_FETCH = TS_R_COLD        ;  carry cold_err unchanged
COLD_GROUPS  = 2
COLD_LAST_TAIL = __COLD_TAIL_TRUST_LOAD__
.else
COLD_R_BUSY  = 9
COLD_R_FETCH = 15
COLD_GROUPS  = 1
COLD_LAST_TAIL = __COLD_TAIL_UI_LOAD__
.endif

REU_STASH = $90                 ; execute, $FF00 trigger off, C64 -> REU
REU_FETCH = $91                 ; execute, $FF00 trigger off, REU -> C64

; Every group runs at cert_buf; a group's image is its run area's first
; LEN bytes, its marker the last one. The PRG carries them back to back.
COLD_RUN      = cert_buf
LEN_UI        = cold_marker_ui + 1 - COLD_RUN
COLD_IMAGE_LEN = COLD_LAST_TAIL + 1 - __COLD_IMAGE_START__

.assert __COLD_RUN_UI_START__ = cert_buf, lderror, "cold bank: COLD_RUN_UI must sit on cert_buf"
.assert __COLD_TAIL_UI_LOAD__ - __TARGET_PROMPT_CODE_LOAD__ = LEN_UI - 1, lderror, "cold bank: UI load/run layouts differ"
.assert __TARGET_PROMPT_CODE_LOAD__ = __COLD_IMAGE_START__, lderror, "cold bank: the UI group must head COLD_IMAGE"
.assert LEN_UI <= CERT_BUF_SIZE, lderror, "cold bank: UI group larger than cert_buf"
.ifdef TRUST_STORE
LEN_TRUST = cold_marker_trust + 1 - COLD_RUN
.assert __COLD_RUN_TRUST_START__ = cert_buf, lderror, "cold bank: COLD_RUN_TRUST must sit on cert_buf"
.assert __COLD_TAIL_TRUST_LOAD__ - __TRUST_STORE_CODE_LOAD__ = LEN_TRUST - 1, lderror, "cold bank: TRUST load/run layouts differ"
.assert __TRUST_STORE_CODE_LOAD__ = __COLD_TAIL_UI_LOAD__ + 1, lderror, "cold bank: the TRUST group must follow the UI group"
.assert LEN_TRUST <= CERT_BUF_SIZE, lderror, "cold bank: TRUST group larger than cert_buf"
.endif
; The REU home (cold_bank.inc), bounded by COLD_IMAGE_MAX so these hold
; for any image that links. Checked against what the LINKED library says
; its tables are (the code-read values reu_config.o exports), not against
; a copy of the numbers: a library that moves its comb tables onto the
; cold home fails this link.
.import LIB_NISTCURVES_REU_BANK_COMB, LIB_NISTCURVES_REU_BANK_MUL
.import LIB_NISTCURVES_REU_OFFSET_COMB_P256, LIB_NISTCURVES_REU_OFFSET_COMB_P384
.import SINK_FLOOR_BANK
COMB_P256_LO = LIB_NISTCURVES_REU_BANK_COMB * $10000 + LIB_NISTCURVES_REU_OFFSET_COMB_P256
COMB_P384_LO = LIB_NISTCURVES_REU_BANK_COMB * $10000 + LIB_NISTCURVES_REU_OFFSET_COMB_P384
COMB_P256_LEN = 256 * 64        ; 256 anchors x (X, Y), API.md "REU map"
COMB_P384_LEN = 256 * 96
COLD_HI = COLD_REU + COLD_IMAGE_MAX
.assert __COLD_IMAGE_SIZE__ = COLD_IMAGE_MAX, lderror, "cold bank: COLD_IMAGE_MAX is not the cfg's COLD_IMAGE size"
.assert COLD_HI <= COMB_P256_LO .or COLD_REU >= COMB_P256_LO + COMB_P256_LEN, lderror, "cold bank: images overlap the linked library's P-256 Lim-Lee table"
.assert COLD_HI <= COMB_P384_LO .or COLD_REU >= COMB_P384_LO + COMB_P384_LEN, lderror, "cold bank: images overlap the linked library's P-384 Lim-Lee table"
.assert COLD_HI <= LIB_NISTCURVES_REU_BANK_MUL * $10000 .or COLD_REU >= (LIB_NISTCURVES_REU_BANK_MUL + 2) * $10000, lderror, "cold bank: images overlap the multiply-row banks"
; The HTTP body sink's region starts at bank SINK_FLOOR_BANK (src/http.s),
; so everything here, and the library's tables, must sit below it.
.assert COLD_HI <= SINK_FLOOR_BANK * $10000, lderror, "cold bank: images reach the HTTP body sink's banks"
.assert COMB_P384_LO + COMB_P384_LEN <= SINK_FLOOR_BANK * $10000 .and COMB_P256_LO + COMB_P256_LEN <= SINK_FLOOR_BANK * $10000, lderror, "the Lim-Lee tables reach the HTTP body sink's banks"
.assert LIB_NISTCURVES_REU_BANK_MUL + 2 <= SINK_FLOOR_BANK, lderror, "the multiply rows reach the HTTP body sink's banks"
.assert COLD_HI <= HTTP_REU_BODY_BASE, error, "cold bank: images overlap the HTTP body area"

.segment "CODE"

; cold_call — Y = COLD_E_*; A/X are the tenant's arguments.
cold_call:
        sta cold_a
        stx cold_x
        sty cold_y
        lda net_tcp_state
        beq @sock_ok            ; CLOSED
        cmp #NET_TCP_CONNECT_FAIL
        bne @busy               ; CONNECTED or ERROR
@sock_ok:
        lda tls_state
        beq @free               ; IDLE
        cmp #TLS_STATE_ERROR
        bne @busy               ; a session owns cert_buf
@free:
        lda cold_stashed        ; nothing stashed this LOAD: cold_g_sum is
        beq @bad                ;  not a sum of anything, the REU unknown
        ldx cold_entry_grp,y
        stx cold_g
        lda cold_g_tail_lo,x
        sta @clear+1
        sta @mark+1
        lda cold_g_tail_hi,x
        sta @clear+2
        sta @mark+2
        lda #COLD_MARK ^ $FF    ; the marker must come from THIS fetch
@clear: sta $FFFF
        jsr cold_group_len      ; X = group
        lda cold_g_reu_lo,x
        sta cold_dreu
        lda cold_g_reu_hi,x
        sta cold_dreu+1
        lda #<COLD_RUN
        ldx #>COLD_RUN
        ldy #REU_FETCH
        jsr cold_dma
        bne @bad                ; the confirm expired
@mark:  lda $FFFF
        cmp #COLD_MARK
        bne @bad                ; no REU, a short DMA, or no image there
        lda #<COLD_RUN
        ldy #>COLD_RUN
        jsr cold_checksum
        ldx cold_g
        cmp cold_g_sum,x
        bne @bad                ; the REU's image is not the PRG's
        lda #0
        sta cold_err
        ldy cold_y
        lda cold_entry_hi,y
        pha
        lda cold_entry_lo,y
        pha
        lda cold_a
        ldx cold_x
        rts                     ; into the tenant, which returns to our caller
@busy:  lda #COLD_R_BUSY
        .byte $2C               ; bit abs: skips the lda below
@bad:   lda #COLD_R_FETCH
        sta cold_err
.ifdef TRUST_STORE
        sta ts_reason
        lda #TS_ST_FAIL
        sta ts_state
        lda #0
        sta ts_found
        sta ts_staged
.endif
        sec
        rts

; cold_bank_init — boot: stash the PRG's COLD_IMAGE into the REU and keep
; each group's XOR. Once per LOAD: cold_stashed is PRG data, so only a
; fresh LOAD reads 0 here. A re-run without one (RUN after 'Q') skips it
; and keeps the first stash, because $C000 is the TCP ring and has held
; server-chosen bytes since: stashing them would run them. Every group's
; marker must be present at its load address, so a LOAD that stopped short
; of the image stashes nothing, and cold_call then refuses every call.
cold_bank_init:
        lda cold_stashed
        bne @out
        ldx #COLD_GROUPS-1      ; every group's marker must have arrived:
@arrived:                       ;  a LOAD cut short is not stashed whole
        lda cold_g_tl_lo,x
        sta @tail+1
        lda cold_g_tl_hi,x
        sta @tail+2
@tail:  lda $FFFF
        cmp #COLD_MARK
        bne @out
        dex
        bpl @arrived
        inc cold_stashed
        lda #<COLD_IMAGE_LEN
        sta cold_dlen
        lda #>COLD_IMAGE_LEN
        sta cold_dlen+1
        lda #<COLD_REU
        sta cold_dreu
        lda #>COLD_REU
        sta cold_dreu+1
        lda #<__COLD_IMAGE_START__
        ldx #>__COLD_IMAGE_START__
        ldy #REU_STASH
        jsr cold_dma
        ldx #COLD_GROUPS-1
@sum:   stx cold_g
        jsr cold_group_len
        lda cold_g_load_lo,x
        ldy cold_g_load_hi,x
        jsr cold_checksum
        ldx cold_g
        sta cold_g_sum,x
        dex
        bpl @sum
@out:   rts

; cold_group_len — X = group: cold_dlen = its image length. X preserved.
cold_group_len:
        lda cold_g_len_lo,x
        sta cold_dlen
        lda cold_g_len_hi,x
        sta cold_dlen+1
        rts

; cold_dma — one transfer of cold_dlen bytes between C64 address A/X and
; REU (bank ^COLD_REU) address cold_dreu; Y = REU_STASH / REU_FETCH.
; Out: A = reu_dma_timeout, Z=1 iff it is 0.
cold_dma:
        sta reu_c64_lo
        stx reu_c64_hi
        lda cold_dreu
        sta reu_reu_lo
        lda cold_dreu+1
        sta reu_reu_hi
        lda #^COLD_REU
        sta reu_reu_bank
        lda cold_dlen
        sta reu_len_lo
        lda cold_dlen+1
        sta reu_len_hi
        lda #0
        sta reu_addr_ctrl       ; both addresses increment
        tya
        jsr reu_execute
        lda reu_dma_timeout
        rts

; cold_checksum — A/Y = a copy of an image, cold_dlen = its length.
; Out: A = the XOR of its bytes.
cold_checksum:
        sta @rd+1
        sty @rd+2
        ldx cold_dlen+1         ; whole pages
        ldy #0
        tya
@next:  cpx #0
        bne @rd
        cpy cold_dlen
        beq @done
@rd:    eor $FFFF,y
        iny
        bne @next
        inc @rd+2
        dex
        jmp @next
@done:  rts

; Per entry: the tenant (minus one, for the rts dispatch) and its group.
cold_entry_lo:
        .lobytes cold_target_prompt-1
.ifdef TRUST_STORE
        .lobytes cold_ts_load-1, cold_ts_stage-1, cold_ts_save-1
        .lobytes cold_tp_pre-1, cold_tp_post-1
.ifdef TRUST_BUNDLE
        .lobytes cold_tb_check-1
.endif
.endif
cold_entry_hi:
        .hibytes cold_target_prompt-1
.ifdef TRUST_STORE
        .hibytes cold_ts_load-1, cold_ts_stage-1, cold_ts_save-1
        .hibytes cold_tp_pre-1, cold_tp_post-1
.ifdef TRUST_BUNDLE
        .hibytes cold_tb_check-1
.endif
.endif
cold_entry_grp:
        .byte COLD_G_UI
.ifdef TRUST_STORE
        .byte COLD_G_TRUST, COLD_G_TRUST, COLD_G_TRUST
        .byte COLD_G_TRUST, COLD_G_TRUST
.ifdef TRUST_BUNDLE
        .byte COLD_G_UI
.endif
.endif
.assert COLD_E_TARGET = 0 .and COLD_E_TS_LOAD = 1 .and COLD_E_TS_STAGE = 2 .and COLD_E_TS_SAVE = 3, error, "cold bank: entry table order"
.assert COLD_E_TP_PRE = 4 .and COLD_E_TP_POST = 5 .and COLD_E_TB_CHECK = 6, error, "cold bank: entry table order"
.assert COLD_G_UI = 0 .and COLD_G_TRUST = 1, error, "cold bank: group table order"

; Per group: image length, REU address (in bank ^COLD_REU), marker's run
; address, the PRG copy's address, and the XOR boot took of it.
cold_g_len_lo:
        .lobytes LEN_UI
.ifdef TRUST_STORE
        .lobytes LEN_TRUST
.endif
cold_g_len_hi:
        .hibytes LEN_UI
.ifdef TRUST_STORE
        .hibytes LEN_TRUST
.endif
cold_g_reu_lo:
        .lobytes COLD_REU + __TARGET_PROMPT_CODE_LOAD__ - __COLD_IMAGE_START__
.ifdef TRUST_STORE
        .lobytes COLD_REU + __TRUST_STORE_CODE_LOAD__ - __COLD_IMAGE_START__
.endif
cold_g_reu_hi:
        .hibytes COLD_REU + __TARGET_PROMPT_CODE_LOAD__ - __COLD_IMAGE_START__
.ifdef TRUST_STORE
        .hibytes COLD_REU + __TRUST_STORE_CODE_LOAD__ - __COLD_IMAGE_START__
.endif
cold_g_tail_lo:
        .lobytes cold_marker_ui
.ifdef TRUST_STORE
        .lobytes cold_marker_trust
.endif
cold_g_tail_hi:
        .hibytes cold_marker_ui
.ifdef TRUST_STORE
        .hibytes cold_marker_trust
.endif
cold_g_tl_lo:                   ; the PRG copy's marker, per group
        .lobytes __COLD_TAIL_UI_LOAD__
.ifdef TRUST_STORE
        .lobytes __COLD_TAIL_TRUST_LOAD__
.endif
cold_g_tl_hi:
        .hibytes __COLD_TAIL_UI_LOAD__
.ifdef TRUST_STORE
        .hibytes __COLD_TAIL_TRUST_LOAD__
.endif
cold_g_load_lo:
        .lobytes __TARGET_PROMPT_CODE_LOAD__
.ifdef TRUST_STORE
        .lobytes __TRUST_STORE_CODE_LOAD__
.endif
cold_g_load_hi:
        .hibytes __TARGET_PROMPT_CODE_LOAD__
.ifdef TRUST_STORE
        .hibytes __TRUST_STORE_CODE_LOAD__
.endif
cold_g_sum:     .res COLD_GROUPS, 0

cold_err:   .byte 0             ; 0, or the last refusal's COLD_R_*
cold_stashed: .byte 0           ; 1 once this LOAD's image is in the REU
cold_g:     .byte 0
cold_dlen:  .word 0
cold_dreu:  .word 0
cold_a:     .byte 0
cold_x:     .byte 0
cold_y:     .byte 0

.segment "COLD_TAIL_UI"
cold_marker_ui:
        .byte COLD_MARK

.ifdef TRUST_STORE
.segment "COLD_TAIL_TRUST"
cold_marker_trust:
        .byte COLD_MARK
.endif
