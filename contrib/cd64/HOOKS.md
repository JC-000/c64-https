# Commodore Desk 64: the https:// side of HANDOFF=1

A prototype of Commodore Desk 64's side of the handoff (`docs/handoff.md`).
It lets CD64's WEB browser open `https://` pages through our `HANDOFF=1`
helper. It is not submitted anywhere: the plan is a pull request to
[mfidder2026/commodore_desk](https://github.com/mfidder2026/commodore_desk)
once the hardware runs pass.

CD64 has no license file, so none of its code is copied here. This
directory holds only what we wrote:

| File | What it is |
|---|---|
| `web_tls.asm` | New file for CD64's `apps/web/`. All of the logic. |
| `build_cd64.sh` | Builds CD64 on Linux/macOS (their build is Windows `.bat`), with our helper added to the disk as `https`. |
| `e2e_cd64.py` | VICE end-to-end test of CD64 and the helper together (no network). |
| `HOOKS.md` | This file: the small edits to CD64's own files, described. |

Developed and tested against commit `82d7ac4` (2026-10-08) of their repo,
with Kick Assembler 5.25. This toolchain builds `cd64`, `web`, `files`,
`boot` and `helptext` byte-identical to their committed `release/CD64.d81`.

## How it works

1. The user opens an `https://` URL in WEB.
2. WEB's fetch routine sees the `https:` scheme and loads `WEBTLS`.
3. `WEBTLS` writes the request into the REU mailbox: an 18-byte template
   plus the URL. It sets `$02FF = $A5` and launches `HTTPS` from drive 8
   through the core's own `launchCommon`, the way the desktop starts any
   program.
4. The helper fetches the page, writes the reply, and loads `CD64` back
   at `$0810`.
5. At startup, the core sees `$02FF = $A5` and opens WEB.
6. WEB's init loads `WEBTLS`, which copies the URL back from the mailbox
   and navigates to it with WEB's normal `nv_Go`.
7. `nv_Go` calls the fetch routine again. This time `WEBTLS` finds a
   reply waiting and feeds the stored headers and body, byte by byte,
   through WEB's existing `nt_Rx`.
8. Redirects, titles, links, the history and the HTML renderer are all
   WEB's own code, unchanged. A redirect to another `https://` URL starts
   another round trip.

**Why a separate `WEBTLS` file.** The WEB overlay ends at `$BF3C` against
a hard limit of `$BFFF`, and its spare bytes are where link storage grows
at runtime. So only a loader and the hooks (87 bytes) stay resident. The
rest (442 bytes) is `webtls.prg`, loaded on demand to `$7000-$7FFF`. WEB's
own header reserves that area for the F1 help, which is modal, so it
cannot be open during a fetch or a launch.

**Why a RAM flag.** The core has 19 bytes free (it runs to `$37EC` against
`$37FF`). The hook there is 15 bytes: test `$02FF`, open app 15. `$02FF` is
outside CD64's page-2 variables (they end near `$023A`) and outside the
KERNAL's own use. A cold start clears it (RAMTAS), so a power-on never
opens WEB by mistake.

## The edits to CD64's own files

| File | Edit |
|---|---|
| `web_main.asm` | Import `apps/web/web_tls.asm`. Define a second segment, `WebTls` at `$7000` (max `$7FFF`), written out as `webtls.prg`. |
| `apps/web/web_net.asm` | In `nt_Fetch`, after the per-fetch variables are reset and before the network is set up: if `WB_NEW+4` is not `':'` (the scheme is `https:`), `jmp hx_Fetch`. |
| `apps/web/web_url.asm` | **`ur_Norm`:** accept a 5-letter `https` scheme (`sec`/`rts`) where it used to return the "not possible" message. **`ur_Parse`:** start the host at index 8 instead of 7 when `WB_NEW+4` is not `':'`. **`orig`** (in `ur_Resolve`): stop looking for the host's end only from index 8. At 7 it cut `https://` short, so `/path` links on an https page resolved wrong. |
| `apps/web/web.asm` | **`wb_Init`:** end with `jsr bm_Page` / `jmp hx_Init` instead of `jmp bm_Page`. **`sWbHttps`:** becomes `"HTTPS FAILED, CODE "` followed by a 2-digit `sHxN`. **Header:** the "http only" comment updated. |
| `kernel/kernel.asm` | `jsr web_Boot` after `jsr cal_Boot` in `kernel_Init`. |
| `kernel/clock.asm` | `web_Boot`, next to `time_Boot` and `cal_Boot`: `lda $02ff` / `cmp #$a5` / `bne` → `rts`; else `lda #15` / `jmp openApp`. |

## What the user sees

- **An `https://` page:** `LOADING HTTPS please wait`, then the helper's
  own screen: progress markers and, with `TRUST_STORE=1`, its trust
  questions. Then CD64 comes back with the page.
- **A failure:** the status line shows `HTTPS FAILED, CODE nn`, with the
  result codes of `docs/handoff.md`. Code `01` means no reply was found;
  code `99` means `WEBTLS` is missing from the disk.

## Known gaps (prototype)

- **No recovery from an interrupted run.** If the machine is reset while
  the helper runs (mailbox state RUNNING), banks 0-2 of the RAM drive stay
  in the helper's save area. `docs/handoff.md` says how to restore them;
  CD64 does not do it yet.
- **History is lost.** After an https page, WEB's history holds only that
  page. CD64 is reloaded from disk, so the browser starts fresh.
- **Every https page is a full TLS handshake**, about 45 s at 48 MHz. That
  includes each redirect hop and each BACK to an https page.
- **The Host header carries no port** (a helper limitation).
- **Links of the form `//host/path` on an https page resolve to `http:`.**
- **Paths over 100 characters are refused** with result code `02`.
  68k.news article URLs run to about 700.
- **Drive 8 is fixed**, as it is everywhere else in CD64's launcher.

## Tests

`e2e_cd64.py`, in VICE with a 16 MB REU and the D81 from `build_cd64.sh`:

1. **Replay:** a DONE reply planted in the REU renders as a page. Nothing
   past the stored body length is fed. The mailbox ends IDLE and `$02FF`
   is cleared.
2. **Launch:** WEB navigates to an `https://` URL. The helper loads from
   the disk, finds no network in VICE, answers code 3 and loads CD64 back.
   WEB then shows `HTTPS FAILED, CODE 03`. Throughout, the URL is
   delivered intact and REU banks 0-7 (the RAM drive) stay byte-identical.

Against their unmodified code, case 1 fails: the page never appears
within its 900 s wait. Case 2 was not reached in that run, because the
outer timeout ended it first. A mutant that drops the end-of-body check in
the feed loop fails case 1.

```
contrib/cd64/e2e_cd64.py <checkout>/build/CD64.d81 <web_main.sym> src/handoff.inc
```

To get `web_main.sym`, run
`java -jar KickAss.jar web_main.asm -symbolfile -odir <dir>` in the
checkout.
