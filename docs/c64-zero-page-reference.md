# C64 Zero Page ($00-$FF) Definitive Reference

## Context and Assumptions

This reference categorizes every zero page byte for a **standalone assembly program** that:
- Starts via `SYS` from a BASIC stub (BASIC is idle after launch)
- May or may not bank out BASIC ROM ($A000-$BFFF)
- Keeps KERNAL ROM active ($E000-$FFFF) for chrout, getin, file I/O
- Has the normal KERNAL IRQ handler at `$EA31` running (~60 Hz via CIA1 Timer A)

## Category Definitions

| Category | Meaning |
|----------|---------|
| **ALWAYS SAFE** | Never touched by KERNAL IRQ handler or any KERNAL call. Free to use at all times. |
| **SAFE (BASIC-only)** | Only used by BASIC interpreter. Once your assembly program has control, these are free — BASIC idle loop does NOT touch them. Safe even across KERNAL calls. |
| **SAFE (no KERNAL I/O)** | Not touched by the IRQ handler, but clobbered by specific KERNAL file I/O routines. Safe as long as you save/restore around those calls. |
| **IRQ-CLOBBERED** | Written by the KERNAL IRQ handler on every interrupt (~60 Hz). Must be saved/restored with SEI/CLI if used while IRQs are enabled. |
| **SYSTEM-RESERVED** | CPU I/O port, or actively used by KERNAL infrastructure that cannot be bypassed. Do not use. |

---

## Quick Summary Table

| Range | Count | Category | Notes |
|-------|-------|----------|-------|
| `$00-$01` | 2 | SYSTEM-RESERVED | 6510 CPU I/O port |
| `$02` | 1 | ALWAYS SAFE | Completely unused by all ROMs |
| `$03-$06` | 4 | SAFE (BASIC-only) | BASIC conversion vectors; not touched after SYS |
| `$07-$72` | 108 | SAFE (BASIC-only) | BASIC interpreter workspace |
| `$73-$8A` | 24 | SAFE (BASIC-only) | CHRGET subroutine; BASIC only |
| `$8B-$8F` | 5 | SAFE (BASIC-only) | RND seed; BASIC only |
| `$90` | 1 | SAFE (no KERNAL I/O) | I/O status; set by KERNAL I/O calls |
| `$91` | 1 | IRQ-CLOBBERED | STOP key flag; written every IRQ |
| `$92-$97` | 6 | SAFE (no KERNAL I/O) | Tape/serial/RS232 workspace |
| `$98` | 1 | SAFE (no KERNAL I/O) | Open file count |
| `$99-$9A` | 2 | SAFE (no KERNAL I/O) | Default I/O device numbers |
| `$9B-$9F` | 5 | SAFE (no KERNAL I/O) | Tape/RS232 workspace |
| `$A0-$A2` | 3 | IRQ-CLOBBERED | Jiffy clock (TI); updated every IRQ |
| `$A3-$AB` | 9 | SAFE (no KERNAL I/O) | Tape/serial/RS232 temporaries |
| `$AC-$AF` | 4 | SAFE (no KERNAL I/O) | LOAD/SAVE pointers |
| `$B0-$B6` | 7 | SAFE (no KERNAL I/O) | Tape/RS232 workspace |
| `$B7-$BC` | 6 | SAFE (no KERNAL I/O) | File parameters (SETLFS/SETNAM) |
| `$BD-$BF` | 3 | SAFE (no KERNAL I/O) | Tape workspace |
| `$C0` | 1 | IRQ-CLOBBERED | Cassette motor interlock; written every IRQ |
| `$C1-$C2` | 2 | SAFE (no KERNAL I/O) | LOAD/SAVE start address |
| `$C3-$C4` | 2 | SAFE (no KERNAL I/O) | LOAD address / temp pointer |
| `$C5` | 1 | IRQ-CLOBBERED | Previous key matrix code; written every IRQ |
| `$C6` | 1 | IRQ-CLOBBERED | Keyboard buffer length; written every IRQ |
| `$C7` | 1 | SAFE (no KERNAL I/O) | Reverse print mode; only CHROUT screen path |
| `$C8-$CA` | 3 | SAFE (no KERNAL I/O) | Screen input cursor save; CHRIN only |
| `$CB` | 1 | IRQ-CLOBBERED | Current key matrix code; written every IRQ |
| `$CC` | 1 | IRQ-CLOBBERED | Cursor flash enable; read every IRQ |
| `$CD` | 1 | IRQ-CLOBBERED | Cursor flash counter; decremented every IRQ |
| `$CE` | 1 | IRQ-CLOBBERED | Character under cursor; written during blink |
| `$CF` | 1 | IRQ-CLOBBERED | Cursor blink phase; toggled every IRQ |
| `$D0` | 1 | SAFE (no KERNAL I/O) | Screen input end-of-line; CHRIN only |
| `$D1-$D2` | 2 | IRQ-CLOBBERED | Screen line pointer; used during cursor blink |
| `$D3` | 1 | IRQ-CLOBBERED | Cursor column; read during cursor blink |
| `$D4` | 1 | SAFE (no KERNAL I/O) | Quote mode; CHROUT screen path |
| `$D5` | 1 | SAFE (no KERNAL I/O) | Screen line length; CHROUT screen path |
| `$D6` | 1 | SAFE (no KERNAL I/O) | Cursor row; CHROUT screen path |
| `$D7` | 1 | SAFE (no KERNAL I/O) | Last PETSCII code; CHROUT screen path |
| `$D8` | 1 | SAFE (no KERNAL I/O) | Insert mode count; CHROUT screen path |
| `$D9-$F2` | 26 | IRQ-CLOBBERED | Screen line link table; used during cursor blink |
| `$F3-$F4` | 2 | IRQ-CLOBBERED | Color RAM pointer; written during cursor blink |
| `$F5-$F6` | 2 | IRQ-CLOBBERED | Keyboard decode table ptr; written every IRQ |
| `$F7-$F8` | 2 | SAFE (no KERNAL I/O) | RS232 input buffer pointer; RS232 only |
| `$F9-$FA` | 2 | SAFE (no KERNAL I/O) | RS232 output buffer pointer; RS232 only |
| `$FB-$FE` | 4 | ALWAYS SAFE | Completely unused by all ROMs |
| `$FF` | 1 | SAFE (BASIC-only) | BASIC float-to-string temp |

---

## Detailed Per-Address Reference

### $00-$01: CPU I/O Port (SYSTEM-RESERVED)

| Addr | Label | Description |
|------|-------|-------------|
| `$00` | D6510 | 6510 data direction register. Controls which bits of $01 are input vs output. Default: `$2F`. **Never use.** |
| `$01` | R6510 | 6510 I/O port. Bits 0-2: ROM/RAM banking (LORAM/HIRAM/CHAREN). Bits 3-5: Datasette control. **Read by IRQ handler** (cassette sense check at $EA61). |

The IRQ handler reads `$01` at `$EA61`, `$EA6B`, `$EA75` and may write it at `$EA79` to control the cassette motor. This is part of the automatic cassette motor shutoff logic.

### $02: ALWAYS SAFE

| Addr | Label | Description |
|------|-------|-------------|
| `$02` | — | Completely unused by BASIC, KERNAL, and IRQ handler. **The single safest zero page byte.** |

### $03-$06: SAFE (BASIC-only)

| Addr | Label | Description |
|------|-------|-------------|
| `$03-$04` | ADRAY1 | Vector: float-to-integer routine (default `$B1AA`). Set once at BASIC cold start. Never read after SYS. |
| `$05-$06` | ADRAY2 | Vector: integer-to-float routine (default `$B391`). Same — set once, never read after SYS. |

These are only used if BASIC evaluates `USR()` or does type conversions. After `SYS`, BASIC is idle and never reads them. **Safe in assembly.**

### $07-$72: SAFE (BASIC-only) — BASIC Interpreter Workspace

This entire range is the BASIC interpreter's working memory. **None of it is touched by the KERNAL IRQ handler.** Once your assembly program has control via SYS, BASIC is in its idle input loop and does NOT actively write to these locations (it only writes when executing BASIC statements).

**Critical nuance**: If BASIC regains control (e.g., your program returns via RTS, or BRK), BASIC will reinitialize many of these. But while your assembly code is running, they are yours.

| Addr | Label | Used By | Description |
|------|-------|---------|-------------|
| `$07` | CHARAC | BASIC | Text scan search character |
| `$08` | ENDCHR | BASIC | Statement terminator search character |
| `$09` | TRMPOS | BASIC | Column position before TAB/SPC |
| `$0A` | VERCK | BASIC | LOAD/VERIFY flag (also at $93 for KERNAL) |
| `$0B` | COUNT | BASIC | Input buffer index / array subscript count |
| `$0C` | DIMFLG | BASIC | DIM/array operation flag |
| `$0D` | VALTYP | BASIC | Data type: $00=numeric, $FF=string |
| `$0E` | INTFLG | BASIC | Numeric type: $00=float, $80=integer |
| `$0F` | GARBFL | BASIC | LIST quote flag / garbage collection flag |
| `$10` | SUBFLG | BASIC | Array subscript / FN call flag |
| `$11` | INPFLG | BASIC | INPUT/GET/READ source flag |
| `$12` | TANSGN | BASIC | Trig sign / comparison result |
| `$13` | CHANNL | BASIC | Current I/O channel (BASIC's own tracking) |
| `$14-$15` | LINNUM | BASIC | Target line number (GOTO/GOSUB/LIST) |
| `$16` | TEMPPT | BASIC | Temp string stack pointer |
| `$17-$18` | LASTPT | BASIC | Pointer to last temp string |
| `$19-$21` | TEMPST | BASIC | Temporary string descriptor stack (9 bytes) |
| `$22-$25` | INDEX | BASIC | Miscellaneous temp pointers (4 bytes) |
| `$26-$2A` | RESHO | BASIC | Multiplication/division work area (5 bytes) |
| `$2B-$2C` | TXTTAB | BASIC | Pointer to BASIC program start (default $0801) |
| `$2D-$2E` | VARTAB | BASIC | Pointer to variable area start |
| `$2F-$30` | ARYTAB | BASIC | Pointer to array area start |
| `$31-$32` | STREND | BASIC | Pointer to array area end |
| `$33-$34` | FRETOP | BASIC | Pointer to bottom of string storage |
| `$35-$36` | FRESPC | BASIC | Current string allocation pointer |
| `$37-$38` | MEMSIZ | BASIC | Highest BASIC memory address |
| `$39-$3A` | CURLIN | BASIC | Current BASIC line number |
| `$3B-$3C` | OLDLIN | BASIC | Previous line number (for CONT) |
| `$3D-$3E` | OLDTXT | BASIC | Pointer to next statement (for CONT) |
| `$3F-$40` | DATLIN | BASIC | Current DATA line number |
| `$41-$42` | DATPTR | BASIC | Pointer to next DATA item |
| `$43-$44` | INPPTR | BASIC | Input result pointer (GET/INPUT/READ) |
| `$45-$46` | VARNAM | BASIC | Current variable name |
| `$47-$48` | VARPNT | BASIC | Pointer to current variable value |
| `$49-$4A` | FORPNT | BASIC | Pointer to FOR loop variable |
| `$4B-$4C` | OPPTR | BASIC | Operator table displacement |
| `$4D` | OPMASK | BASIC | Comparison operator mask |
| `$4E-$4F` | DEFPNT | BASIC | Pointer to current FN descriptor |
| `$50-$52` | DSCPNT | BASIC | Temp string descriptor pointer (3 bytes) |
| `$53` | FOUR6 | BASIC | Garbage collection step size (3 or 7) |
| `$54-$56` | JMPER | BASIC | JMP instruction for function dispatch |
| `$57-$5B` | — | BASIC | Arithmetic register #3 (5 bytes) |
| `$5C-$60` | — | BASIC | Arithmetic register #4 (5 bytes) |
| `$61` | FACEXP | BASIC | FAC exponent |
| `$62-$65` | FACHO | BASIC | FAC mantissa (4 bytes) |
| `$66` | FACSGN | BASIC | FAC sign |
| `$67` | SGNFLG | BASIC | Series evaluation term count |
| `$68` | BITS | BASIC | FAC overflow/rounding byte |
| `$69` | ARGEXP | BASIC | ARG exponent |
| `$6A-$6D` | ARGHO | BASIC | ARG mantissa (4 bytes) |
| `$6E` | ARGSGN | BASIC | ARG sign |
| `$6F` | ARISGN | BASIC | FAC1 vs FAC2 sign comparison |
| `$70` | FACOV | BASIC | Low-order rounding byte |
| `$71-$72` | FBUFPT | BASIC | Series evaluation / polynomial pointer |

### $73-$8A: SAFE (BASIC-only) — CHRGET Subroutine

| Addr | Label | Description |
|------|-------|-------------|
| `$73-$8A` | CHRGET | 24-byte machine language subroutine copied from ROM at cold start. Contains self-modifying code with text pointer at `$7A-$7B`. **Only called by BASIC interpreter** — never by KERNAL or IRQ handler. |

This is executable code, not data. If you overwrite it, BASIC cannot function, but that is irrelevant if BASIC is not running. **Completely safe for assembly use.** The 24 contiguous bytes at `$73-$8A` are prime zero page real estate.

### $8B-$8F: SAFE (BASIC-only) — RND Seed

| Addr | Label | Description |
|------|-------|-------------|
| `$8B-$8F` | RNDX | 5-byte floating-point seed for BASIC's RND() function. Only written by RND(). **Safe in assembly.** |

### $90: SAFE (no KERNAL I/O) — I/O Status

| Addr | Label | Description |
|------|-------|-------------|
| `$90` | STATUS/ST | KERNAL I/O status word. Written by LOAD, SAVE, serial bus, tape, and RS232 routines. Read by READST ($FFB7). **Not touched by IRQ handler.** Safe if you save/restore around KERNAL I/O calls. |

### $91: IRQ-CLOBBERED — STOP Key

| Addr | Label | Description |
|------|-------|-------------|
| `$91` | STKEY | STOP key flag. **Written every single IRQ** by the jiffy clock routine at `$F6DA`. The UDTIM routine (`$F69B`) scans keyboard row 7 and stores the result here. `$7F` = STOP pressed, `$FF` = not pressed. |

**IRQ code path**: `$EA31` -> JSR `$FFEA` -> JMP `$F69B` (UDTIM) -> `$F6DA: STA $91`

### $92-$97: SAFE (no KERNAL I/O) — Tape/Serial/RS232

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$92` | SVXT | Tape timing constant | Tape LOAD/SAVE |
| `$93` | VERCK | LOAD vs VERIFY flag | LOAD ($FFD5) |
| `$94` | C3PO | Serial bus output cache flag | Serial bus I/O |
| `$95` | BSOUR | Serial bus buffered output byte | Serial bus I/O |
| `$96` | SYNO | Tape sync number | Tape I/O |
| `$97` | XSAV | Temp X/Y register save | CHRIN tape, GETIN RS232 |

### $98-$9A: SAFE (no KERNAL I/O) — File Management

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$98` | LDTND | Number of open I/O files (0-10) | OPEN, CLOSE |
| `$99` | DFLTN | Default input device (0=keyboard) | CHKIN, CLRCHN |
| `$9A` | DFLTO | Default output device (3=screen) | CHKOUT, CLRCHN |

### $9B-$9F: SAFE (no KERNAL I/O) — Tape/RS232

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$9B` | PRTY | Tape character parity | Tape I/O |
| `$9C` | DPSW | Tape byte-received flag | Tape I/O |
| `$9D` | MSGFLG | KERNAL message control | SETMSG ($FF90) |
| `$9E` | PTR1 | Tape error log index | Tape I/O |
| `$9F` | PTR2 | Tape correction index | Tape I/O |

### $A0-$A2: IRQ-CLOBBERED — Jiffy Clock

| Addr | Label | Description |
|------|-------|-------------|
| `$A0` | TIME+0 | Jiffy clock high byte |
| `$A1` | TIME+1 | Jiffy clock mid byte |
| `$A2` | TIME+2 | Jiffy clock low byte |

**Written every single IRQ.** The UDTIM routine at `$F69B` increments `$A2`, carrying into `$A1` and `$A0`. Resets to 0 at `$4F1A01` (approximately 24 hours). This is the TI/TI$ clock.

**IRQ code path**: `$EA31` -> JSR `$FFEA` -> JMP `$F69B` -> INC `$A2` (always), INC `$A1`/`$A0` (on carry)

### $A3-$AB: SAFE (no KERNAL I/O) — Tape/Serial/RS232 Temporaries

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$A3` | — | EOI flag / tape bit counter | Serial bus / tape I/O |
| `$A4` | — | Serial input buffer / tape parity | Serial bus / tape I/O |
| `$A5` | CNTDN | Serial/tape bit counter / sync count | Serial bus / tape I/O |
| `$A6` | BUFPNT | Tape I/O buffer byte offset | Tape I/O, CHRIN tape |
| `$A7` | INBIT | RS232 input bits / tape temp | RS232 / tape I/O |
| `$A8` | BITCI | RS232 input bit count / tape temp | RS232 / tape I/O |
| `$A9` | RINONE | RS232 start bit check flag | RS232 I/O |
| `$AA` | RIDATA | RS232 input byte buffer / tape temp | RS232 / tape I/O |
| `$AB` | RIPRTY | RS232 input parity / tape leader count | RS232 / tape I/O |

**Not using tape or RS232?** These 9 bytes are effectively free. Not touched by IRQ handler.

### $AC-$AF: SAFE (no KERNAL I/O) — LOAD/SAVE Pointers

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$AC-$AD` | SAL | SAVE current pointer / scroll temp | LOAD, SAVE, screen scroll |
| `$AE-$AF` | EAL | LOAD end address | LOAD, SAVE |

CHROUT to screen may use `$AC-$AD` during scrolling. Save/restore around CHROUT if using these.

### $B0-$B6: SAFE (no KERNAL I/O) — Tape/RS232

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$B0-$B1` | CMP0 | Tape timing work area | Tape I/O |
| `$B2-$B3` | TAPE1 | Tape buffer pointer (default $033C) | Tape I/O |
| `$B4` | BITTS | RS232 output bit count / tape temp | RS232 / tape I/O |
| `$B5` | NXTBIT | RS232 next output bit / tape EOT | RS232 / tape I/O |
| `$B6` | RODATA | RS232 output byte buffer | RS232 I/O |

**Not using tape or RS232?** These 7 bytes are free. Not touched by IRQ handler.

### $B7-$BC: SAFE (no KERNAL I/O) — File Parameters

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$B7` | FNLEN | Filename length | SETNAM, OPEN, LOAD |
| `$B8` | LA | Current logical file number | SETLFS, OPEN, CLOSE, CHKIN, CHKOUT |
| `$B9` | SA | Current secondary address | SETLFS, OPEN, CLOSE, LOAD |
| `$BA` | FA | Current device number | SETLFS, OPEN, CLOSE, LOAD |
| `$BB-$BC` | FNADR | Pointer to filename | SETNAM, OPEN, LOAD |

These are the "parameters" for KERNAL file operations. **SETLFS writes $B8/$B9/$BA. SETNAM writes $B7/$BB/$BC.** Every OPEN/CLOSE/LOAD/SAVE reads them. Between KERNAL I/O calls, they retain their values and are safe to read. Not touched by IRQ handler.

### $BD-$BF: SAFE (no KERNAL I/O)

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$BD` | ROPRTY | RS232 output parity / tape temp | RS232 / tape I/O |
| `$BE` | FSBLK | Tape block counter | Tape I/O |
| `$BF` | MYCH | Tape input byte work area | Tape I/O |

### $C0: IRQ-CLOBBERED — Cassette Motor Interlock

| Addr | Label | Description |
|------|-------|-------------|
| `$C0` | CAS1 | Cassette motor interlock flag. **Written by IRQ handler** at `$EA69` (`STY $C0` where Y=0). The IRQ handler checks cassette sense line on $01 bit 4 and clears $C0 when no tape button is pressed. |

### $C1-$C4: SAFE (no KERNAL I/O)

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$C1-$C2` | STAL | I/O start address for LOAD/SAVE | LOAD, SAVE |
| `$C3-$C4` | — | LOAD forced address / temp pointer | LOAD (via $F49E) |

### $C5-$C6: IRQ-CLOBBERED — Keyboard State

| Addr | Label | Description |
|------|-------|-------------|
| `$C5` | LSTX | Matrix code of **previously** pressed key. **Written every IRQ** by keyboard scan at `$EB28` (`STY $C5`). |
| `$C6` | NDX | Number of characters in keyboard buffer. **Read and written every IRQ** by keyboard scan at `$EB21`/`$EB35`/`$EB40`. |

### $C7: SAFE (no KERNAL I/O) — Reverse Mode

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$C7` | RVS | Reverse video mode flag (0=normal, $12=reverse) | CHROUT screen path ($E716) |

### $C8-$CA: SAFE (no KERNAL I/O) — Screen Input State

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$C8` | INDX | Input line end column | CHRIN (screen input) |
| `$C9` | LXSP+0 | Cursor row at start of input | CHRIN (screen input) |
| `$CA` | LXSP+1 | Cursor column at start of input | CHRIN (screen input) |

### $CB: IRQ-CLOBBERED — Current Key

| Addr | Label | Description |
|------|-------|-------------|
| `$CB` | SFDX | Matrix code of **currently** pressed key (64=none). **Written every IRQ** by keyboard scan at `$EA8E` (initial `$40`) and `$EAC9` (when key found). |

### $CC-$CF: IRQ-CLOBBERED — Cursor Blink

| Addr | Label | Description |
|------|-------|-------------|
| `$CC` | BLNSW | Cursor blink enable. **Read every IRQ** at `$EA34`. 0=blink enabled. If you set this to non-zero, the IRQ skips the blink code and `$CD-$CF` are not touched. |
| `$CD` | BLNCT | Cursor blink countdown timer. **Decremented every IRQ** at `$EA38` when blink is enabled. Reset to `$14` (20) when it reaches zero. |
| `$CE` | GDBLN | Screen code of character under cursor. **Written during blink** at `$EA4D`. |
| `$CF` | BLNON | Cursor blink phase (0=character visible, 1=cursor visible). **Shifted/toggled every IRQ** at `$EA42`/`$EA4B`. |

**Optimization tip**: Setting `$CC` to non-zero (cursor off) prevents the IRQ handler from touching `$CD`, `$CE`, `$CF`, `$D1-$D2`, `$D3`, `$F3-$F4`, and the screen line link table `$D9-$F2`. This dramatically reduces IRQ zero page interference.

### $D0: SAFE (no KERNAL I/O)

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$D0` | CRSW | Input source flag (0=keyboard, 3=screen) | CHRIN |

### $D1-$D3: IRQ-CLOBBERED (when cursor blinks)

| Addr | Label | Description |
|------|-------|-------------|
| `$D1-$D2` | PNT | Pointer to current screen line. **Used by IRQ cursor blink** — the blink code at `$EA47` does `LDA ($D1),Y` and at `$EA1E` does `STA ($D1),Y`. Also **written by `$EA24`** subroutine which derives color pointer from it. |
| `$D3` | PNTR | Cursor column (0-39). **Read by IRQ cursor blink** at `$EA40` (`LDY $D3`) and `$EA1C` (`LDY $D3`). |

### $D4-$D8: SAFE (no KERNAL I/O) — Screen Editor State

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$D4` | QTSW | Quote mode flag (0=normal, 1=quote) | CHROUT screen path |
| `$D5` | LNMX | Current screen line length (39 or 79) | CHROUT screen path |
| `$D6` | TBLX | Physical cursor row (0-24) | CHROUT screen path |
| `$D7` | — | Last PETSCII code / data temp | CHROUT screen path |
| `$D8` | INSRT | Insert mode character count | CHROUT screen path |

### $D9-$F2: IRQ-CLOBBERED (when cursor blinks) — Screen Line Link Table

| Addr | Label | Description |
|------|-------|-------------|
| `$D9-$F1` | LDTB1 | 25-byte screen line link table. High bytes of pointers to each screen line (rows 0-24). Bit 7 indicates whether the line is the first physical line of a logical line. **Read by the cursor blink code path** — when `$EA24` computes the color RAM pointer from `$D1-$D2`, the screen line table is the source of those pointers. CHROUT to screen also uses these when moving the cursor. |
| `$F2` | — | Screen editor temp / scroll work | Screen scroll during CHROUT |

### $F3-$F4: IRQ-CLOBBERED (when cursor blinks) — Color RAM Pointer

| Addr | Label | Description |
|------|-------|-------------|
| `$F3-$F4` | USER | Pointer to current position in Color RAM. **Written every IRQ** during cursor blink by the `$EA24` subroutine: `$F3` gets low byte from `$D1`, `$F4` gets high byte derived from `$D2`. Also used by `$EA21` (`STA ($F3),Y`) and `$EA52` (`LDA ($F3),Y`). |

### $F5-$F6: IRQ-CLOBBERED — Keyboard Decode Table Pointer

| Addr | Label | Description |
|------|-------|-------------|
| `$F5-$F6` | KEYTAB | Pointer to keyboard decode table. **Written every IRQ** by keyboard scan at `$EA9D-$EAA1` (initial setup to `$EB81`) and by `$EB6F-$EB74` (shift/CTRL/C= table selection). |

### $F7-$FA: SAFE (no KERNAL I/O) — RS232 Buffer Pointers

| Addr | Label | Description | Clobbered By |
|------|-------|-------------|--------------|
| `$F7-$F8` | RIBUF | RS232 input buffer pointer | RS232 OPEN/CLOSE |
| `$F9-$FA` | ROBUF | RS232 output buffer pointer | RS232 OPEN/CLOSE |

**Not using RS232?** These 4 bytes are free. Not touched by IRQ handler. **However**, note that CLOSE of an RS232 device writes `$F8` and `$FA` (see `$F2C1-$F2C3`).

### $FB-$FE: ALWAYS SAFE

| Addr | Label | Description |
|------|-------|-------------|
| `$FB` | — | Completely unused by BASIC, KERNAL, and IRQ handler. |
| `$FC` | — | Completely unused. |
| `$FD` | — | Completely unused. |
| `$FE` | — | Completely unused. |

These 4 bytes are **universally acknowledged** as the safest zero page locations on the C64. Every reference (Programmer's Reference Guide, Mapping the C64, c64-wiki, sta.c64.org) confirms they are unused.

### $FF: SAFE (BASIC-only)

| Addr | Label | Description |
|------|-------|-------------|
| `$FF` | BTEFM | Temporary byte used by BASIC's float-to-string conversion. Only touched during BASIC PRINT of floating-point numbers. **Not touched by KERNAL or IRQ handler.** Safe in assembly. |

---

## IRQ Handler ($EA31) Complete Zero Page Footprint

The following addresses are read or written on **every single interrupt** (~60 times/second):

### Always touched (every IRQ):
| Addr | Operation | Code Path |
|------|-----------|-----------|
| `$01` | Read (and possibly write) | `$EA61`: cassette sense check |
| `$91` | Write | `$F6DA` via UDTIM: STOP key column |
| `$A0` | Read/Write (on carry) | `$F6A5`/`$F6B6` via UDTIM: jiffy clock high |
| `$A1` | Read/Write (on carry) | `$F6A1`/`$F6B8` via UDTIM: jiffy clock mid |
| `$A2` | Read/Write (always) | `$F69D`/`$F6BA` via UDTIM: jiffy clock low |
| `$C0` | Read/Write | `$EA69`/`$EA71`: cassette motor interlock |
| `$C5` | Read/Write | `$EAE5`/`$EB28`: previous key matrix code |
| `$C6` | Read/Write | `$EB21`/`$EB35`/`$EB40`: keyboard buffer count |
| `$CB` | Write | `$EA8E`: current key matrix code (set to $40 initially) |
| `$CC` | Read | `$EA34`: cursor blink enable check |
| `$F5-$F6` | Write | `$EA9D-$EAA1`: keyboard decode table pointer |

### Touched only when cursor blink is enabled ($CC = 0):
| Addr | Operation | Code Path |
|------|-----------|-----------|
| `$CD` | Read/Write | `$EA38`/`$EA3E`: blink countdown |
| `$CE` | Read/Write | `$EA4D`/`$EA5A`: character under cursor |
| `$CF` | Read/Write | `$EA42`/`$EA4B`: blink phase |
| `$D1-$D2` | Read | `$EA47`: screen line pointer (indirect) |
| `$D3` | Read | `$EA40`/`$EA1C`: cursor column |
| `$F3-$F4` | Write | `$EA26`/`$EA2E`: color RAM pointer |

### Touched only during keyboard decode (key pressed):
| Addr | Operation | Code Path |
|------|-----------|-----------|
| `$CB` | Write (updated) | `$EAC9`: actual key matrix code |
| `$F5-$F6` | Write (updated) | `$EB6F-$EB74`: shift-state decode table |

---

## KERNAL Call Zero Page Side Effects

### CHROUT ($FFD2) — to screen (device 3)
Reads: `$9A`, `$D3`, `$D5`, `$D6`
Writes: `$C7`, `$D0-$D8`, `$D1-$D2` (screen line ptr), `$D9-$F1` (line link table during scroll), `$F3-$F4` (color ptr), `$AC-$AD` (during scroll)

### CHROUT ($FFD2) — to serial bus
Reads: `$9A`, `$94`, `$95`, `$90`
Writes: `$90`, `$94`, `$95`

### CHRIN ($FFCF) — from keyboard
Reads: `$99`, `$D3`, `$D6`, `$D5`, `$C6`
Writes: `$C8`, `$C9`, `$CA`, `$D0`, `$D1-$D2`, `$D3-$D6`

### GETIN ($FFE4) — from keyboard
Reads: `$99`, `$C6`
Writes: `$97` (if RS232), `$C6` (decrements buffer count)

### SETLFS ($FFBA)
Writes: `$B8` (logical file), `$B9` (secondary addr), `$BA` (device)

### SETNAM ($FFBD)
Writes: `$B7` (name length), `$BB-$BC` (name pointer)

### OPEN ($FFC0)
Reads: `$B7`, `$B8`, `$B9`, `$BA`, `$BB-$BC`, `$98`
Writes: `$90`, `$98`, `$B9`, `$A6` (tape), `$F7-$FA` (RS232)

### CLOSE ($FFC3)
Reads: `$B9`, `$BA`, `$98`
Writes: `$98`, `$99`, `$9A`, `$F8`, `$FA` (RS232 close)

### LOAD ($FFD5)
Reads: `$B7`, `$B9`, `$BA`, `$C3-$C4`
Writes: `$90`, `$93`, `$AE-$AF`, `$B9`, `$C3-$C4`

### SAVE ($FFD8)
Reads: `$AE-$AF`
Writes: `$90`, `$AE-$AF`, `$C1-$C2`

### CLRCHN ($FFCC)
Writes: `$99` (reset to 0), `$9A` (reset to 3)

### CHKIN ($FFC6) / CHKOUT ($FFC9)
Reads: `$B8`, `$B9`, `$BA`, `$98`
Writes: `$99` or `$9A`

---

## Practical Recommendations for Assembly Programs

### Best Zero Page Allocations (with KERNAL + IRQ active)

**Tier 1 — Guaranteed safe at all times (5 bytes):**
```
$02       ; 1 byte - universally safe
$FB-$FE   ; 4 bytes - universally safe
```

**Tier 2 — Safe while your code runs, BASIC idle (137 bytes: $03-$8F):**
```
$03-$06   ; 4 bytes - BASIC conversion vectors
$07-$72   ; 108 bytes - BASIC workspace (huge!)
$73-$8A   ; 24 bytes - CHRGET (contiguous block!)
$8B-$8F   ; 5 bytes - RND seed
$FF        ; 1 byte - BASIC float temp
```

The entire range `$02-$8F` plus `$FB-$FE` plus `$FF` gives you **143 bytes** of safe zero page, as long as BASIC is idle (it is, after SYS).

**Tier 3 — Safe if you don't use tape/RS232 (31 more bytes):**
```
$92, $96        ; 2 bytes - tape-only
$9B-$9C         ; 2 bytes - tape-only
$9E-$9F         ; 2 bytes - tape-only
$A3-$AB         ; 9 bytes - tape/serial temp (but serial TALK/LISTEN use some)
$B0-$B6         ; 7 bytes - tape/RS232
$BD-$BF         ; 3 bytes - tape
$F7-$FA         ; 4 bytes - RS232 buffer pointers
```

**Tier 4 — Safe between KERNAL I/O calls (save/restore around calls):**
```
$90             ; I/O status
$93-$95, $97    ; serial/tape workspace
$98-$9A         ; file count + default devices
$9D             ; message flag
$AC-$AF         ; LOAD/SAVE pointers (also scroll temp)
$B7-$BC         ; file parameters
$C1-$C4         ; LOAD/SAVE addresses
$C7-$CA         ; screen input state
$D0, $D4-$D8   ; screen editor state
```

### Disabling Cursor Blink ($CC = non-zero)

Setting `STA $CC` with a non-zero value (e.g., `LDA #$01 : STA $CC`) disables cursor blinking. This prevents the IRQ handler from touching:
- `$CD-$CF` (blink counter/phase/character)
- `$D1-$D3` (screen line pointer, cursor column — not written, only read if blink fires)
- `$F3-$F4` (color RAM pointer)

This frees up to **8 more bytes** from IRQ interference, though `$D1-$D3` and `$F3-$F4` are still written by CHROUT.

### cc65 Runtime Zero Page Usage

The cc65 C compiler for the C64 allocates its ZEROPAGE segment at **`$0002-$001B`** (26 bytes). This covers:
- Software stack pointer
- Extended accumulator (sreg)
- General purpose registers (ptr1-ptr4, tmp1-tmp4, regbank)

This range overlaps with `$02` (free), `$03-$06` (BASIC vectors), and `$07-$1B` (BASIC workspace). Since cc65 programs take over from BASIC, there is **no conflict** — both cc65 and pure assembly agree these are safe.

If writing assembly that must coexist with cc65-compiled code, **avoid `$02-$1B`** and use `$1C-$8F` or `$FB-$FE` instead.

---

## Sources

- sta.c64.org/cbm64mem.html — Commodore 64 memory map
- c64-wiki.com/wiki/Zeropage — C64 Wiki zero page reference
- pagetable.com/c64ref/c64mem/ — Ultimate Commodore 64 Reference memory map
- pagetable.com/c64ref/kernal/ — KERNAL API reference
- skoolkid.github.io/sk6502/c64rom/ — C64 ROM disassembly (EA31, EA87, EB48, F69B, EA24, EA1C, E716, F1CA, F4A5, F5DD, F34A, F291, F13E)
- cc65.github.io/doc/c64.html — cc65 C64 documentation
- github.com/cc65/cc65/blob/master/cfg/c64.cfg — cc65 linker config (ZP: start=$0002, size=$001A)
- Sheldon Leemon, "Mapping the Commodore 64" (Project 64 digital edition)
- Commodore, "C64 Programmer's Reference Guide"
