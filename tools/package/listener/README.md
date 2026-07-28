# c64-https TLS 1.3 test listener

A self-contained TLS 1.3 HTTPS listener that stands up the **entire server
side** of the c64-https end-to-end test on a fresh machine — including
minting its own certificate. No dependency on the c64-https repo or the
`c64-test-harness` package.

It is a stand-alone clone of the inline listener in the c64-https repo
(`tools/uci/test_https_local.py`). The protocol behavior is copied
verbatim so the Commodore 64 client sees exactly what it expects.

## What it does

- Serves **TLS 1.3 only** (min = max pinned to TLS 1.3). The C64 advertises
  a single cipher suite, `TLS_AES_128_GCM_SHA256`, which the stdlib server
  offers among its TLS 1.3 defaults and selects.
- Presents a self-signed **ECDSA P-256** (`secp256r1`, `ecdsa-with-SHA256`)
  leaf certificate. The C64 verifies the CertificateVerify signature against
  this leaf key, so a freshly generated self-signed cert is sufficient —
  it is *not* a trust anchor and must never be deployed anywhere real.
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

## Run it

```sh
./run.sh                 # default port 443, auto-fallback to 4433
./run.sh --port 4433     # unprivileged port, no root needed
./run.sh --serve-forever # keep accepting connections
```

`run.sh` creates a local `.venv`, installs `cryptography` (the only
third-party dependency; the TLS server itself is pure stdlib `ssl`),
generates `certs/server.{pem,key}` if absent, and starts the listener.

Point the C64 client (or the c64-https test) at this machine's LAN IP on
the chosen port. Default port 443 needs root to bind; if that fails the
listener automatically falls back to 4433.

## Files

| File               | Purpose                                                   |
|--------------------|-----------------------------------------------------------|
| `run.sh`           | One-shot: venv + deps + certs + start listener            |
| `listener.py`      | The TLS 1.3 listener (stdlib `ssl`)                       |
| `gen_certs.py`     | Mint a fresh P-256 self-signed cert into `certs/`         |
| `requirements.txt` | `cryptography` (cert generation only)                     |

## Regenerate the certificate

```sh
python gen_certs.py --force                 # fresh P-256 cert/key
python gen_certs.py --cn example.test --san example.test
```

By default the CN is `www.foo.bar` with SANs `foo.bar` and `www.foo.bar`,
matching the c64-https test fixtures.
