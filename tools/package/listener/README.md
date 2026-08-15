# c64-https TLS 1.3 test listener

A TLS 1.3 HTTPS listener that stands up the **entire server side** of the
c64-https end-to-end test on a fresh machine — including minting its own
certificate. No dependency on the c64-https repo, on `c64-test-harness`, or on
any third-party Python package.

It is a stand-alone clone of the inline listener in the c64-https repo
(`tools/uci/rig_https_local.py`). The protocol behavior is copied verbatim so
the Commodore 64 client sees exactly what it expects.

## Dependencies: none. Requirement: a Python that can do TLS 1.3.

There is nothing to `pip install` and no venv to create.

The one thing this cannot supply for itself is a property of the interpreter:
an `ssl` module with TLS 1.3, i.e. one linked against **OpenSSL 1.1.1 or
newer**. macOS's `/usr/bin/python3` is linked against LibreSSL 2.8.3, has no
TLS 1.3 at all, and will refuse with a one-line message — use python.org or
Homebrew `python3` there. Most Linux distributions ship a suitable python3.

Historically this package needed `cryptography` to generate its certificate.
It no longer does: `gen_certs.py` implements P-256 keygen, DER encoding and
ECDSA-SHA256 signing in pure Python. TLS itself was always the stdlib. That
removal is what lets the whole thing ship as one self-extracting `.py`.

## What it does

- Serves **TLS 1.3 only** (min = max pinned to TLS 1.3). The C64 advertises a
  single cipher suite, `TLS_CHACHA20_POLY1305_SHA256` (0x1303), which the
  stdlib server offers among its TLS 1.3 defaults and selects.
- Presents a self-signed **ECDSA P-256** (`secp256r1`, `ecdsa-with-SHA256`)
  leaf certificate, freshly generated on first run into `./certs/`. The C64
  verifies the CertificateVerify signature against this leaf key, so a
  self-signed cert is sufficient — it is *not* a trust anchor and **must never
  be deployed anywhere real**.
- Reads one request and replies with the fixed canonical response:

  ```
  HTTP/1.0 200 OK\r\n
  Content-Length: 21\r\n
  \r\n
  HELLO FROM TLS SERVER
  ```

  The C64's HTTP parser requires a 3-digit status code and a
  `Content-Length: ` header with a **single space after the colon** — this
  response matches byte-for-byte.
- Handles one connection then exits (pass `--serve-forever` to keep going).
- Writes `server_result.json` (listening / client_addr / request / cipher /
  error), matching the schema the reference harness emits.

Certs, `server_result.json` and any other output land in the **current
directory**, not next to the script: the shipped single-file build extracts
itself into a throwaway temp dir, so anchoring on `__file__` would hide them.

## Run it

As the shipped single file:

```sh
python3 c64-https-listener.py                # port 443, auto-falls back to 4433
python3 c64-https-listener.py --port 4433    # unprivileged
python3 c64-https-listener.py --serve-forever
python3 c64-https-listener.py --selftest     # prove it works, no C64 needed
python3 c64-https-listener.py --extract ./src  # unpack these sources
python3 c64-https-listener.py --help
```

Or straight from these sources:

```sh
python3 listener.py --port 4433
python3 listener.py --selftest
```

## Proving it works without a C64

`--selftest` mints a cert into a temp dir, serves on loopback, and drives
itself with a Python `ssl` client, then — where an `openssl s_client`
supporting `-ciphersuites` is available — with a client restricted to
`TLS_CHACHA20_POLY1305_SHA256`, the only suite the C64 offers. That second
round matters: CPython exposes no API to restrict TLS 1.3 suites, so the
stdlib client always picks AES-256-GCM and would never catch a server that
could not speak ChaCha20 to the C64. Where openssl is missing the round is
reported as SKIP, not as a failure.

Exit code 0 means PASS.

## Errors

Every failure is one human-readable line, not a traceback: no TLS 1.3 in this
Python, port already in use, unreadable cert. Pass `--debug` to get the
traceback back if you are working on the listener itself.
