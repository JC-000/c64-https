# tests/ — manual live-rig scripts

Everything in this directory is a **manual** script. Each is a `main()`
program behind `if __name__ == "__main__": sys.exit(main())`, each needs a
live network rig (and usually `sudo`), and each takes minutes to tens of
minutes to run. They are not part of any automated suite and nothing in
`make` or `tools/run_all_tests.py` invokes them.

They are named `rig_*.py`, **not** `test_*.py`, and that is deliberate —
see "Why not pytest" below.

| Script | Rig | What it proves |
|---|---|---|
| `rig_phase1_dhcp.py` | Linux `br-c64` bridge + RR-Net | ip65 acquires a DHCP lease |
| `rig_phase2_http.py` | Linux `br-c64` bridge + RR-Net | plain HTTP GET end to end |
| `rig_phase3_https.py` | Linux `br-c64` bridge + RR-Net | HTTPS handshake + GET |
| `rig_phase3_https_1mhz.py` | Linux `br-c64` bridge + RR-Net | the same at honest 1 MHz, no warp |
| `rig_vice_https_macos.py` | macOS feth pair + pcap, no hardware | HTTPS handshake + GET, hardware-free |

Setup lives in `scripts/setup-bridge-tap.sh` (Linux) and
`tools/rig-up-macos.sh` (macOS); the macOS rig additionally needs a VICE
built with the pcap driver's `geteuid()==0` gate patched out. See the
"End-to-End Bridge Tests" and "VICE ip65 rig" sections of `README.md` and
`CLAUDE.md` for the full prerequisites.

Run them directly:

```sh
sudo PYTHONPATH=tools python3 tests/rig_phase1_dhcp.py
sudo PYTHONPATH=tools python3 tests/rig_phase2_http.py
sudo env VICE_HTTPS_OK_TO_RUN=1 PYTHONPATH=tools python3 tests/rig_phase3_https_1mhz.py
python3 tests/rig_vice_https_macos.py
```

Each prints `PASS` or `FAIL` and exits non-zero on failure. They verify
properly — `rig_vice_https_macos.py`, for instance, hard-fails on
`FAIL: DHCP not acquired after 3 attempts` and only prints `PASS` after a
completed TLS handshake and HTTP response.

## Why not pytest

These scripts cannot be pytest tests without inventing a rig fixture, and
a rig fixture that quietly skips is worse than no fixture at all: it turns
"nobody ran the network tests" into a green-looking run with a skip nobody
reads.

Until they were renamed they were called `tests/test_*.py`, which is
exactly pytest's discovery convention — so `pytest` at the repo root
walked this directory, found no `def test_` functions, collected zero, and
said nothing about it. The pass count it printed came entirely from
`tools/`, and read like whole-project coverage. That was issue #109.

The `rig_` prefix keeps them out of pytest's namespace no matter which
directory you invoke from — which is the part that had to be a rename
rather than config, since `testpaths` in `pytest.ini` only takes effect
when pytest is run from the repo root. `conftest.py` then prints what a
pytest run does and does not cover, in the header and again in the
summary. `tools/test_pytest_boundary.py` fails if a `test_*.py` file
reappears here.

`tools/uci/` is the same directory shape for real U64E/C64U hardware and
was renamed the same way in the follow-up to #111; see
`tools/uci/README.md`. The guard covers both directories, and also fails
if `pytest.ini`'s `norecursedirs` stops listing either of them.
