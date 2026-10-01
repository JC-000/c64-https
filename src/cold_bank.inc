; src/cold_bank.inc — the comb cold-code bank's entries, groups and REU home
;
; #155 phase 2. Shared by src/net/uci/cold_bank.s (the trampoline and its
; tables) and the tenants' resident stubs (src/boot.s,
; src/net/uci/trust_store.s): a stub is `ldy #COLD_E_x / jmp cold_call`.
;
; A GROUP is one image: segments linked together to run in cert_buf, so
; they may call each other. Groups never run at the same time (each one's
; fetch overwrites the last), so a group is up to cert_buf's 2 KB on its
; own, and code that calls into another tenant belongs in that tenant's
; group. Each group ends in its own COLD_TAIL_* marker byte.

.ifndef COLD_BANK_INC_INCLUDED
COLD_BANK_INC_INCLUDED = 1

COLD_G_UI       = 0             ; TARGET_PROMPT_CODE, COLD_TAIL_UI
COLD_G_TRUST    = 1             ; TRUST_STORE_CODE, COLD_TAIL_TRUST (TRUST_STORE=1)

COLD_E_TARGET   = 0             ; https_target_prompt     (COLD_G_UI)
COLD_E_TS_LOAD  = 1             ; trust_store_load        (COLD_G_TRUST)
COLD_E_TS_STAGE = 2             ; trust_store_stage       (COLD_G_TRUST)
COLD_E_TS_SAVE  = 3             ; trust_store_save        (COLD_G_TRUST)

; Where the images live in the REU: bank 2 from $A000, laid out as the PRG
; carries them at COLD_IMAGE. Bank 2 $0000-$3FFF is comb's P-256 Lim-Lee
; table and $4000-$9F9F the P-384 one (parked, not deleted: libs/nistcurves
; API.md's REU map, "$9FA0-$FFFF safe for consumer use"). reu_layout.inc's
; $20100/$22100/$24100 overlay slots sit inside the P-256 table and are
; never used here. cold_bank.s asserts the images stay in
; [COLD_REU_FLOOR, bank 3) and below HTTP_REU_BODY_BASE.
COLD_REU        = $02A000
COLD_REU_FLOOR  = $029FA0
COLD_IMAGE_MAX  = $1000         ; the cfg's COLD_IMAGE size: every group

COLD_MARK       = $5C           ; each group's last byte

.endif
