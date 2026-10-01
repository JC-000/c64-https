; src/trust_store.inc — the on-disk TOFU trust store: format and API codes.
;
; Issue #155 phase 2, lane L2. Format per S3 §5 (phase-2 spike notes):
;
;   header   8 B   "C6TS", version, generation (16-bit LE), record count N
;   records  N x 64 B, fixed
;   trailer  8 B   SHA-256(header || records), first 8 bytes
;
; The trailer is a CHECKSUM, not a MAC: it catches torn writes and bit rot.
; Anyone who can write the medium can also recompute it.
;
; Two slots, <prefix>A and <prefix>B (TRUST_STORE_DIR/TRUST.A, .B). Load
; validates both and takes the valid one with the newer generation (serial
; arithmetic, RFC 1982 on 16 bits); save writes the OTHER slot, closes it
; and reads it back. Opening a file for write empties it, so a torn save
; only ever damages the slot that was not loaded.
;
; tools/trust_store.py is the host-side mirror of this file; keep the two
; in step (tools/test_trust_store_format.py checks the constants).

TS_MAGIC_0      = 'C'
TS_MAGIC_1      = '6'
TS_MAGIC_2      = 'T'
TS_MAGIC_3      = 'S'
TS_VERSION      = 1

TS_HDR_VER      = 4             ; header offsets
TS_HDR_GEN      = 5             ; 2 B, little-endian
TS_HDR_N        = 7
TS_HDR_SIZE     = 8
TS_SUM_SIZE     = 8
TS_REC_SIZE     = 64
TS_MAX_RECS     = 32
TS_FILE_MAX     = TS_HDR_SIZE + TS_MAX_RECS * TS_REC_SIZE + TS_SUM_SIZE

; Record fields (offsets into a 64 B record)
TS_REC_KEY      = 0             ; 16 B: SHA-256(lowercased host)[0..15]
TS_REC_SPKI     = 16            ; 32 B: SHA-256 of the leaf SPKI
TS_REC_MODE     = 48            ; 1 B:  TS_MODE_*
TS_REC_FLAGS    = 49            ; 1 B
TS_REC_USES     = 50            ; 2 B:  use count, little-endian
TS_REC_DISPLAY  = 52            ; 12 B: display prefix, non-authoritative
TS_KEY_SIZE     = 16

TS_MODE_TOFU     = 1
TS_MODE_ACCEPTED = 2
TS_MODE_OVERRIDE = 3

; ts_state
TS_ST_NONE      = 0             ; never loaded
TS_ST_VALID     = 1             ; a slot validated; lookup is meaningful
TS_ST_EMPTY     = 2             ; both slots FILE DOESN'T EXIST
TS_ST_FAIL      = 3             ; fail closed; ts_reason says why

; Per-slot results (ts_slot_st) and ts_reason share one code space.
TS_SLOT_OK      = 0
TS_SLOT_ABSENT  = 1             ; "FILE DOESN'T EXIST"
TS_R_NOPATH     = 2             ; "PATH DOESN'T EXIST": no medium or no dir
TS_R_DOS        = 3             ; any other open failure, or a UCI timeout
TS_R_IO         = 4             ; read/close failed, or the file is too big
TS_R_FORMAT     = 5             ; bad magic, or size != 16 + 64 * N
TS_R_VERSION    = 6             ; unknown version
TS_R_CHECKSUM   = 7
TS_R_TIE        = 8             ; both slots valid, neither is newer
TS_R_BUSY       = 9             ; a TCP socket is connected (the ring is live)
TS_R_NOTREADY   = 10            ; save with no VALID/EMPTY load or no record
TS_R_CHANGED    = 11            ; the store changed on disk since the load
TS_R_FULL       = 12            ; TS_MAX_RECS records and the host is new
TS_R_WRITE      = 13            ; open/write/close of the target slot failed
TS_R_VERIFY     = 14            ; read-back is not the generation just written
TS_R_COLD       = 15            ; uci-comb: the cold bank could not run the store
                                ;  (src/net/uci/cold_bank.s)
