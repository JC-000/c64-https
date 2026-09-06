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
| `rig_ip65_rrnet_hw.py` | macOS `en4` + a PHYSICAL RR-Net in the U64E | HTTPS handshake + GET on real CS8900a silicon |

`rig_ip65_rrnet_hw.py` is the only one of these that runs the ip65 backend
on real hardware; every other ip65 result in this repo came from an
emulator. Every **wire and memory** verdict comes from
`tools/ip65_hw_checks.py`, and `tools/test_ip65_hw_checks_unit.py` (in
pytest's `testpaths`, no hardware, milliseconds) proves each of those
alarms on a known-bad input, with `tools/mutate_ip65_hw_checks.py`
breaking each one to prove the suite goes red. The rig itself is not
judgment-free — 15 delegated verdicts against 18 of its own procedural
assertions (screen scrapes, the config write, the listener probe, the
selftests), which have no red case — so a run's headline check count
should not be read as that many facts about the cartridge. Its segment is
10.0.66.0/24,
deliberately not the feth rig's 10.0.65.0/24, so both rigs can be up at
once and real silicon can be compared against the emulated pair.

**A green run does not mean the ip65 product validates server names.**
`src/x509_name.s` is UCI-only, so the ip65 image accepts any certificate
that verifies, whatever name it carries; this rig fetches from a local
listener with a self-signed leaf and asserts nothing about the name in it.
Do not cite the rig as coverage of that gap — it is the gap.

Setup lives in `scripts/setup-bridge-tap.sh` (Linux),
`tools/rig-up-macos.sh` (macOS feth pair) and
`tools/rig-up-rrnet-macos.sh` (the physical RR-Net segment); the macOS
VICE rig additionally needs a VICE built with the pcap driver's
`geteuid()==0` gate patched out. See the
"End-to-End Bridge Tests" and "VICE ip65 rig" sections of `README.md` and
`CLAUDE.md` for the full prerequisites.

Run them directly:

```sh
sudo PYTHONPATH=tools python3 tests/rig_phase1_dhcp.py
sudo PYTHONPATH=tools python3 tests/rig_phase2_http.py
sudo env VICE_HTTPS_OK_TO_RUN=1 PYTHONPATH=tools python3 tests/rig_phase3_https_1mhz.py
python3 tests/rig_vice_https_macos.py

# the physical RR-Net rig: two sudo commands by hand first, then no sudo
sudo bash tools/rig-up-rrnet-macos.sh en4
sudo tcpdump -i en4 -n -s0 -U -w /tmp/rrnet-https.pcap   # leave running
U64_HOST=10.43.23.81 python3 tests/rig_ip65_rrnet_hw.py
```

`rig_ip65_rrnet_hw.py` runs at a stock 1 MHz because
`c64-https-ip65-onchip.prg` is the stock-C64 product, so budget ~40-80
minutes for the fetch; it exits 78 (inconclusive) rather than 0 when a
check could not be decided, and reports a timeout as a timeout.

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
