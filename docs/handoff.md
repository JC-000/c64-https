# HANDOFF=1 — one HTTPS GET for a host program

`make BACKEND=uci USE_NISTCURVES_ONCHIP=1 TRUST_STORE=1 PQ_HYBRID=1 HANDOFF=1`
builds a helper PRG, not a product. A host program writes a request into
the REU, loads the helper, and gets control back once the helper has fetched
the page. The first host is the WEB browser in Commodore Desk 64 (CD64).
`src/handoff.inc` is the normative layout and this page is the prose
version. Where they disagree, the `.inc` file wins.

## What the host needs

- **An Ultimate (U64E or C64 Ultimate) with the command interface enabled.**
  The helper does TCP and DNS through UCI, like the shipped UCI images.
  Turbo matters: a handshake takes about 45 s at 48 MHz (local listener,
  measured), and roughly 35 minutes at 1 MHz.
- **A REU of 1 MB or more.** Banks 0–7 stay the host's (CD64's RAM drive
  R:30 uses at most 512 KB). The helper uses banks 8–11 and the body goes
  from bank 12 to the REU's end. A 16 MB REU gives a 15.25 MB body.
- **The helper PRG on a drive the host can LOAD from**, and the host's own
  PRG on the drive named in the request.

The comb image (`USE_NISTCURVES_ONCHIP_COMB=1`) is refused for now. It
loads over `$C000-$CFFF`, where CD64's launcher keeps the SYS parser it
jumps through right after the LOAD.

## REU map

| REU address | Owner | Contents |
|---|---|---|
| `$000000-$07FFFF` | host | Left as it was. The helper writes banks 0–2 and offset 0 of banks 4, 8, 16, …, 128 while it runs. It saves banks 0–2 first and restores them before it returns, and it puts the probe bytes back before anything else runs. |
| `$080000-$0AFFFF` | helper | The saved copy of banks 0–2 while a request runs. |
| `$0B0000-$0B015F` | host → helper | Request (fixed fields and the URL) |
| `$0B0180-$0B018F` | helper → host | Reply |
| `$0B0200-$0B11FF` | helper → host | Response head, raw: status line and headers exactly as received, CR LF included, up to 4 KB |
| `$0C0000-` end | helper → host | Response body, de-chunked |

## Request (the host writes it before the LOAD)

| Offset | Size | Field |
|---|---|---|
| `$00` | 8 | `"C64HTTPS"` (ASCII) |
| `$08` | 1 | version = `1` |
| `$09` | 1 | state = `$01` REQUEST |
| `$0A` | 1 | device to load the host back from (8–30) |
| `$0B` | 1 | length of the host's file name (1–16) |
| `$0C` | 2 | address to JMP to after loading the host, little-endian (CD64: `$0810`) |
| `$0E` | 16 | host file name, PETSCII |
| `$20` | 320 | the URL: ASCII, NUL-terminated, `https://host[:port][/path or ?query]` |

The first 14 bytes plus the name are fixed for a given host program, so a
host can keep them as one template (CD64's is 18 bytes) and add only the
URL.

URL rules:
- **Scheme:** `https://`, in any letter case.
- **Host:** 1–63 characters of `[A-Za-z0-9.-]`, with no empty label. It is
  lowercased.
- **Port:** 1–65535. Without one, the helper uses 443.
- **Path:** 1–100 characters in `!`–`~` (no spaces or control characters;
  percent-encode them). A bare `?query`, or no path at all, gets a leading
  `/`.

A request that fails these rules is answered with result `2`, and nothing
is dialled. Unusable return fields (device, name length, entry) fall back
to CD64's own reload: `"CD64"`, device 8, `$0810`.

The `Host:` header carries the host name only, without the port.

## Reply (the helper writes it, then sets state `$03` DONE)

| Offset | Size | Field |
|---|---|---|
| `$180` | 1 | result (below) |
| `$181` | 2 | HTTP status, binary, LE (0 = none) |
| `$183` | 3 | body bytes stored at `$0C0000` |
| `$186` | 3 | body bytes received |
| `$189` | 1 | flags: `$01` complete, `$02` body outgrew the REU, `$04` head over 4 KB (cut), `$08` handshake completed (server Finished verified, name checked), `$10` X25519MLKEM768 negotiated |
| `$18A` | 2 | head bytes stored at `$0B0200` |
| `$18C` | 1 | `net_last_error` |
| `$18D` | 1 | trust verdict (`cert_pin_status`, `src/trust_policy.inc`) |

Results:

| Code | Meaning |
|---|---|
| `0` | the whole body arrived (Content-Length or the last chunk) |
| `2` | bad request: version, port, host or path |
| `3` | network init or DHCP failed |
| `4` | DNS |
| `5` | TCP connect |
| `6` | TLS: handshake, certificate, name check or pin |
| `7` | sending the request |
| `8` | response incomplete |
| `9` | body larger than the REU region |
| `10` | not dialled: the trust policy refused (or the user answered N) |

Redirects are the host's to follow: a `3xx` arrives as a reply like any
other, with its `Location:` in the head.

## States and recovery

`$01` REQUEST (host) → `$02` RUNNING (helper, after saving banks 0–2) →
`$03` DONE (helper, after restoring them). The host sets it back to `$00`
once it has read the reply.

If the host starts and finds `$02`, the helper never finished: it crashed,
or the machine was reset. Banks 0–2 then hold the helper's own data, and
the host's original contents are at `$080000-$0AFFFF`. Copy them back,
then clear the state.

If the REU is under 1 MB, or no `$01` request is present, the helper prints
why, waits for a key, writes nothing to the REU, and loads the default host.

## What the user sees

The helper owns the screen while it runs: the same progress lines as the
shipped UCI image (`CH`, `SH`, `KEYS`, … `RX`) and, under `TRUST_STORE=1`,
the same trust questions. Examples are a first-use notice, `ACCEPT ON
RETRY? A=YES` when a server's key has changed, and `CONTINUE UNPINNED?
Y/N` when the store cannot be read. RESTORE is ignored while it runs. The
host's own RESTORE handler lives at `$C000`, which is the helper's TCP ring.

Then it writes the reply, restores banks 0–2, scrubs the session keys,
zero page and stack exactly as `Q` does, and loads the host with a stub at
`$C000`: KERNAL `LOAD name,dev,1` and then `JMP entry`. A failed LOAD
cold-resets the machine.

## Limits (v1)

- Certificates: the chain is not checked against any CA. That has always
  been true of this client: trust is the name check plus trust on first
  use (`TRUST.A`/`TRUST.B`). P-256 leaves only, so a site with an RSA
  certificate fails with result `6`.
- Paths up to 100 characters. 68k.news article URLs run to ~700 and will
  be refused with result `2` until `http_req_buf` grows.
- Servers that need SNI-less ALPN, HTTP/2 only, or a ~15 s handshake
  deadline (Cloudflare) do not work.

## Tests

`tools/test_handoff.py` runs in VICE with no network. It starts the helper
the way a host would, from a 16 MB REU image holding a known pattern and a
request, with stand-in host programs on drive 8. For accepted URLs (checking
the parsed host, port and path) and refused ones (scheme, host, path,
port), no request, and a 512 KB REU, it checks the reply, the
DONE state, a byte-for-byte untouched host REU (banks 0–7 and every probe
bank), the saved copy in banks 8–10, and that the right program was
entered at the right address. The fetch itself, a reply with a body,
needs a device: see the UCI rigs.
