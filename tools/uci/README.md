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
`_sni_precondition.py`, `_ecdsa_vectors.py`, `_analyze_ecdsa_trace.py`.
`_sni_precondition.py` is pure logic and carries its own checks:

```sh
python3 tools/uci/_sni_precondition.py --selftest
```

Three of the rigs delegate rather than duplicate: `rig_https_print_body.py`
and `rig_https_local_p384.py` both import `rig_https_local` and override a
narrow slice of it (the response body, and the cert/key pair
respectively), so a change to the shared flow lands in all three.

## Running them

```sh
U64_HOST=10.43.23.81 python3 tools/uci/boot_check.py
U64_HOST=10.43.23.81 python3 tools/uci/rig_https_local.py
```

The three rigs that talk to a **local** TLS listener — `rig_https_local.py`,
its two wrappers, and `rig_https_bad_finished.py` — need a PRG built with an
SNI override (issue #141):

```sh
make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP=1 HTTPS_SNI=www.foo.invalid
```

The C64 dials the dev host's dotted-quad IP, because the firmware needs an
address; but `src/x509_name.s` (v0.4.2+) checks the certificate's SAN
dNSName entries against `tls_hostname`, and an IP literal matches no
dNSName, so the client correctly rejects the handshake at Certificate
(`tls_state=$FF`, `tls_last_state=$04`). `HTTPS_SNI=` presents the cert's
name while leaving the connect host alone. The `make clean` is load-bearing:
`HTTPS_SNI=` adds `-D HTTPS_SNI_OVERRIDE=1`, which make cannot see, so a
stale `http.o` yields a *mixed link* that embeds the name but never runs the
override — a build that fails identically to no SNI at all. Each of those
rigs checks both halves offline, before `DeviceLock`, so a wrong PRG costs
no device time.

`U64_HOST` selects the device (default `192.168.1.81`). Everything goes
through the `c64-test-harness` package's `DeviceLock` plus
`enable_uci`/`disable_uci` — never drive the device's REST API directly
and never `pkill` a run you did not start, because the device is shared
across the `c64-*` repos and the lock queue is the only thing keeping
concurrent sessions from clobbering each other.

### Queueing for the device — `C64_DEVICE_LOCK_TIMEOUT`

Every script here, plus `tests/rig_ip65_rrnet_hw.py` and
`tools/test_ecdsa_p384_kat.py`'s U64 arm, takes the lock through
`acquire_device_lock()` in `_device_lock_helper.py` (or passes
`lock_timeout_s()` where the harness takes the lock for you), which owns
the one acquire budget: **`C64_DEVICE_LOCK_TIMEOUT` seconds, default
1800 (30 min)**. Nothing keeps its own any more, and
`tools/test_device_lock_timeout.py` fails if anything grows one back —
including a literal `lock_timeout=` passed to `UnifiedManager`, which is
how the thirteenth budget hid from the first version of that guard.

```sh
C64_DEVICE_LOCK_TIMEOUT=7200 python3 tools/uci/rig_https_live.py   # queue for 2 h
```

That budget is **not** the longest run you may queue behind. The
harness's `acquire` is queue aware: while the holder's PID is alive and
its lockfile mtime is fresh, the deadline is re-armed on every poll, so a
waiter sits behind one long healthy holder indefinitely. The budget
bounds the waits it refuses to extend — a dead or wedged holder, and a
**handoff chain**: after the **fourth** change of holder identity the
harness stops extending for the rest of that acquire, and then the
budget is everything. Four, not three: `_MAX_HOLDER_HANDOFFS` is 3 but
extension survives `handoffs <= 3`, so the harness's docstring is one
out and its WARNING text is right. Several lanes cycling one U64E would
hit that within seconds, which is why 120 s could fail against a device
that was merely busy — the mechanism is lab-measured; no timeout from a
real run here has been captured.

A malformed value (`30m`, `2 min`, `0`) is a hard error before the device
is touched, not a silent fall back to the default: the override exists so
a lane can say "I know I am behind an 80-minute run", and a typo that
quietly reinstated 1800 s would fail it later against a budget nobody
asked for. `C64_DEVICE_LOCK_TIMEOUT=` (empty) falls back, with a notice.

While waiting, a line goes to **stderr** every 30 s naming the elapsed
wait, the budget, the holder PID, the **lockfile age** (flagged `STALE,
holder may be wedged` past the 60 s progress window) and the queue depth
— a silent half-hour block is indistinguishable from a hang, and the age
is the field that tells a healthy long run from a wedged one without
waiting out the whole budget for the final diagnostic. Nothing is added
to stdout, which stays parseable.

Other environment variables read by scripts here: `TURBO_MHZ`,
`TURBO_SETTLE`, `HTTPS_PORT`, `BOOT_TIMEOUT`, `ACCEPT_TIMEOUT`,
`SENTINEL_POLL_TIMEOUT`, `C64_INIT_WAIT`, `DEBUG_CAPTURE`,
`UCI_DEBUG_DIR`, `KEEP_DEBUG_ON_PASS`, `EXTERNAL_LISTENER`,
`EXTERNAL_HOST`, `EXTERNAL_PORT`, `FINISHED_MODE`, `BACKEND`,
`ECDSA_MHZ_LIST`, `ECDSA_REPEATS`, `ECDSA_POLL_S`, `ECDSA_DEBUG_CAPTURE`,
`ECDSA_DEBUG_DIR`, `C64_DEVICE_LOCK_TIMEOUT` (above). See each script's docstring for which ones it honors
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
