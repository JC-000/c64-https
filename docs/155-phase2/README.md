# #155 phase 2: design record (UCI trust store)

The design inputs behind the UCI trust store, typed hostnames, the signed pin
bundle and the trust policy. The code is merged (#258, #260-#262, #266, #268,
#269); this folder is kept because the tree cites it (`DECISIONS N`,
`S3 §5`). Figures are pinned to the master commit each file names; re-measure
before reusing one. ip65 is out of scope (`TRUST_STORE=1` is an `$(error)`
there).

| File | What it is |
|---|---|
| `DECISIONS.md` | The binding user decisions, items 1-11. Every `DECISIONS N` cite in the tree means this file. |
| `S3-trust-design.md` | Trust semantics (precedence, record/first-use rules) and the 64 B record format. Raw survey data in `data/`. |
| `L3-design.md` | The trust-policy state machine and sizing; §6 holds the questions DECISIONS 11 answers. |
| `S4-reu-banking.md` | REU code-banking study. Not built beyond the comb cold bank; read before banking more code. |

## S1 storage findings (2026-09-30, U64E, master ac7099d)

These were measured on hardware for the store's disk I/O and are not written
down anywhere else.

- Use the UCI DOS target on persistent media (`/USB1`), never `/Temp`, which is a RAM disk lost at power-off [inferred].
- Speed at 48 MHz: save ~130 ms and load ~77 ms on `/USB1` (~29/30 ms on `/Temp`). KERNAL drive 8 takes 2.5-3 s per save, drive-bound.
- Not found: "FILE DOESN'T EXIST" vs "PATH DOESN'T EXIST" (no medium). Classify on `buf[0]=='F' && buf[5]=='D'`.
- Opening an existing file for write empties it, and nothing is durable until close; a C64 reset mid-replace destroyed the old record. Hence DECISIONS 6: ping-pong `TRUST.A` / `TRUST.B` slots plus read-back verify.
- One WRITE_DATA stores at most 891 B, not 892.
- A read error can report a stale "00,OK" [inferred], so always check the byte count.
- A handle left open across a C64 reset leaks in the firmware [inferred].
- VICE has no UCI emulation, so the DOS path is testable only on a device.

## S2 memory

The reclaims R1-R4 merged as #260, each knob-gated with a re-arm switch
(DECISIONS 2 and 5). Current margins come from `tools/measure_margins.py`,
never from the figures recorded at the time.
