# tools/uci/ — manual hardware-rig scripts (UCI backend)

Everything runnable in this directory is a **manual** script. Each is a
`main()` program behind `if __name__ == "__main__": sys.exit(main())`, each
needs a real UCI device on the LAN (an Ultimate 64 Elite or a C64
Ultimate), and the HTTPS ones take one to twenty minutes per run. They are
not part of any automated suite: nothing in `make` or
`tools/run_all_tests.py` invokes them.

The rig scripts are named `rig_*.py`, **not** `test_*.py`, and that is
deliberate — see "Why not pytest" below.

| Script | What it proves |
|---|---|
| `boot_check.py` | UCI firmware detection + boot banner |
| `phase2_check.py` | DHCP acquire + local-IP readback |
| `phase3_tcp_echo.py` | TCP connect / send / recv against a local echo server |
| `rig_http_local.py` | plain HTTP GET against a local test server |
| `rig_http_live.py` | plain HTTP GET against a real internet host |
| `rig_https_local.py` | full TLS 1.3 handshake + HTTP GET (ECDSA-P256 cert) |
| `rig_https_bad_finished.py` | the negative path: the client must ABORT on a forged server Finished |
| `rig_https_print_body.py` | issue #28 — the decrypted body renders correctly on screen |
| `rig_https_local_p384.py` | the P-384 cert profile (blocked: no P-384 PRG builds today) |
| `bench_ecdsa_u64e.py` | ECDSA-P256 verify wall-clock across a clock sweep |

Files with a leading underscore are helper modules, not entry points:
`_device_lock_helper.py`, `_memory_policy.py`, `_reu_preflight.py`,
`_ecdsa_vectors.py`, `_analyze_ecdsa_trace.py`.

Three of the rigs delegate rather than duplicate: `rig_https_print_body.py`
and `rig_https_local_p384.py` both import `rig_https_local` and override a
narrow slice of it (the response body, and the cert/key pair
respectively), so a change to the shared flow lands in all three.

## Running them

```sh
U64_HOST=10.43.23.81 python3 tools/uci/boot_check.py
U64_HOST=10.43.23.81 python3 tools/uci/rig_https_local.py
```

`U64_HOST` selects the device (default `192.168.1.81`). Everything goes
through the `c64-test-harness` package's `DeviceLock` plus
`enable_uci`/`disable_uci` — never drive the device's REST API directly
and never `pkill` a run you did not start, because the device is shared
across the `c64-*` repos and the lock queue is the only thing keeping
concurrent sessions from clobbering each other.

Other environment variables read by scripts here: `TURBO_MHZ`,
`TURBO_SETTLE`, `HTTPS_PORT`, `BOOT_TIMEOUT`, `ACCEPT_TIMEOUT`,
`SENTINEL_POLL_TIMEOUT`, `C64_INIT_WAIT`, `DEBUG_CAPTURE`,
`UCI_DEBUG_DIR`, `KEEP_DEBUG_ON_PASS`, `EXTERNAL_LISTENER`,
`EXTERNAL_HOST`, `EXTERNAL_PORT`, `FINISHED_MODE`, `BACKEND`,
`ECDSA_MHZ_LIST`, `ECDSA_REPEATS`, `ECDSA_POLL_S`, `ECDSA_DEBUG_CAPTURE`,
`ECDSA_DEBUG_DIR`. See each script's docstring for which ones it honors
and what the defaults are; `CLAUDE.md`'s "UCI test scripts" section has
the prose.

Each prints `PASS` or `FAIL` and exits non-zero on failure.

## Why not pytest

These scripts cannot be pytest tests without inventing a hardware
fixture, and a hardware fixture that quietly skips is worse than no
fixture at all: it turns "nobody has a U64E plugged in" into a
green-looking run with a skip nobody reads.

Until they were renamed they were called `tools/uci/test_*.py`, which is
exactly pytest's discovery convention — so pytest would walk this
directory, find no `def test_` functions, collect zero, and say nothing
about it. That is the same defect issue #109 fixed in `tests/`; PR #111
closed the default-invocation path here with `norecursedirs` but left the
names, because the rename's blast radius through `CLAUDE.md` needed its
own change. This is that change.

`tools/test_pytest_boundary.py` now fails if a `test_*.py` file reappears
in either rig directory, and also if `pytest.ini`'s `norecursedirs` stops
listing one of them. The rename is what holds from an arbitrary working
directory (`testpaths` only applies at the rootdir); `norecursedirs` is
what keeps a root-level run out of here entirely. Both halves are pinned.
