# RR-Net rig helper spec (`c64-https-rrnet-rig-up.sh` / `-down.sh`)

Requirements for a pair of root-owned, sudo-allowlisted host helpers to
replace `sudo bash tools/rig-up-rrnet-macos.sh en4 [down]`, built and
reviewed in new-computer-setup (`privileged/helpers/`, REVIEW.md), installed
beside the feth pair in `/usr/local/libexec/c64-harness/`. The feth pair
(`c64-https-rig-up.sh` / `-rig-down.sh`) is the model: fixed `PATH`, `umask
022`, `cd /`, no arguments, the root-owned dnsmasq copy in that directory
(never a `PATH` or brew lookup), dnsmasq dropped to `nobody:nobody`, state
in root-owned `/var/run/c64-harness` and `/var/log/c64-harness`.

Consumer: `tests/rig_ip65_rrnet_hw.py` (real RR-Net cartridge in the U64E,
cabled directly to a USB-Ethernet NIC on the Mac). See the "Physical RR-Net
rig" section of `CLAUDE.md`.

## Addressing (must match exactly)

| item | value | why |
|---|---|---|
| segment | `10.0.66.0/24` | NOT `10.0.65.0/24`: the feth rig owns `10.0.65.1` on feth1 and both rigs run at once |
| host / gateway / DNS / listener | `10.0.66.1`, netmask `255.255.255.0` | the link has no route off itself; the HTTPS listener binds here |
| DHCP pool | `10.0.66.10`-`10.0.66.60`, lease `1h` | |
| pinned lease | `00:0e:3a:64:64:64` -> `10.0.66.200` | ip65's built-in CS8900a MAC; checkers assert the exact address |
| DHCP options | router = `10.0.66.1`, dns-server = `10.0.66.1`, `--dhcp-authoritative` | |
| DNS | `--address=/www.foo.invalid/10.0.66.1` only, `--no-resolv`, `--conf-file=/dev/null` | answers for one name and forwards nothing, so a pass cannot come from somewhere else |
| bind | `--interface=<NIC> --bind-interfaces --except-interface=lo0 --listen-address=10.0.66.1` | `lo0` exclusion: resident DNS on 127.0.2.x loopback aliases |
| logging | `--log-dhcp --log-queries` | |

`tests/rig_ip65_rrnet_hw.py` and `tools/test_ip65_hw_checks_unit.py` read
`HOST_IP`, `C64_IP`, `C64_MAC` and `TEST_HOST` from
`tools/rig-up-rrnet-macos.sh` via `ip65_hw_checks.rig_const()`. Keep those
four as plain `NAME=value` shell assignments in the helper too, so the repo
side can point `rig_const()` at the installed helper (the same pattern
`tools/test_reserved_test_host.py` uses for the feth helper).

## Interface selection

The current script takes the NIC as `$1`. The allowlist takes no
arguments, and BSD names are not stable: they differ between Macs and move
when an adapter is re-plugged (on the current Mac `en4` is Thunderbolt 2,
not an Ethernet adapter). So:

- a root-owned config file written at install time (e.g.
  `/usr/local/etc/c64-harness/rrnet.conf`) names the adapter by its **MAC
  address**; the helpers resolve it to an `enX` at run time and refuse to
  start when no interface or more than one carries it;
- never accept it from the caller's environment (`env_reset` drops it
  anyway).

**Which adapter, on the current Mac: not cabled yet (2026-10-20).** The
candidates are the two "Ethernet Adapter" ports (en2, en3); en5 (Belkin
USB-C LAN) is currently linked at 1000baseT, so it is not the RR-Net. Record the
MAC when the RR-Net is connected (it will show `status: active` at
`10baseT`).

## rig-up must

1. Refuse arguments, non-root and non-Darwin (exit 64 / 77 / 2, as the feth helper).
2. Check the NIC exists and is `status: active`, else fail with "cable
   connected and C64 powered on?" (a CS8900a lights the link only with
   cartridge power). Warn, do not fail, when media is not `10baseT`: an
   RR-Net is 10 Mbps only, so anything faster is probably the wrong NIC.
3. Refuse when any other process is already listening on `10.0.66.1:53` or
   `:67` (two rigs cannot share the address).
4. `ifconfig <NIC> inet 10.0.66.1 netmask 255.255.255.0 up`.
5. **Truncate the lease file and the log unconditionally**, even when
   dnsmasq is already running. `--log-facility` appends and the lease file
   outlives a restart, so a stale `DHCPACK ... 10.0.66.200` line would
   otherwise read as "the C64 took a lease" with the C64 powered off.
6. Start dnsmasq (flags above) with pid
   `/var/run/c64-harness/rrnet-dnsmasq.pid`, leases
   `/var/run/c64-harness/rrnet-dnsmasq.leases`, log
   `/var/log/c64-harness/rrnet-dnsmasq.log`. Idempotent: an already running
   instance (verified by `comm` = the libexec dnsmasq and `user` = nobody,
   not by the pid alone) is left alone. Fail if it does not stay up.
7. The lease and log files must stay readable by the invoking user: a human
   reads them when diagnosing, though the rig decides nothing from them.

## rig-down must

1. Stop only the dnsmasq its pidfile names, after the same `comm` + `user`
   check; ignore a malformed pidfile or a symlink.
2. Return the NIC to DHCP addressing (`ipconfig set <NIC> DHCP`).
3. Leave the feth rig (10.0.65.x) untouched.

## Not the helpers' job

- The packet capture stays hand-started (`sudo tcpdump -i <NIC> -n -s0 -U
  -w …`). `-s0` and `-U` are both required by `tools/ip65_hw_checks.py`.
  If it should run unattended, that is a third helper with a fixed output
  path, reviewed separately.
- IP forwarding / NAT: the segment is deliberately isolated.

## Repo-side follow-up once installed

- `tests/rig_ip65_rrnet_hw.py`: call the helpers via `sudo -n` the way
  `tests/rig_vice_https_macos.py` does (up only if needed, down only if it
  brought the rig up), and repoint `RIG_SCRIPT`/`rig_const()`.
- Delete `tools/rig-up-rrnet-macos.sh` and update the `sudo bash` lines in
  `tests/rig_ip65_rrnet_hw.py`, `CLAUDE.md` and `tests/README.md`.
