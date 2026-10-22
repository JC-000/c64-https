# RR-Net rig helper spec (`rrnet-rig-up.sh` / `rrnet-rig-down.sh`)

**Status: built and installed** (new-computer-setup 4be92f7, 2026-10-21;
first live run passed with the cartridge cabled). Shared with c64-wireguard,
hence the names carry no `c64-https-` prefix. This file is the spec as
amended to what was built; where the build differs from the first draft, the
text below says what was built and why.

Requirements for a pair of root-owned, sudo-allowlisted host helpers that
replaced `sudo bash tools/rig-up-rrnet-macos.sh en4 [down]` (deleted), built and
reviewed in new-computer-setup (`privileged/helpers/`, REVIEW.md), installed
beside the feth pair in `/usr/local/libexec/c64-harness/`. The feth pair
(`c64-https-rig-up.sh` / `-rig-down.sh`) is the model: fixed `PATH`, `umask
022`, `cd /`, no arguments, the root-owned dnsmasq copy in that directory
(never a `PATH` or brew lookup), dnsmasq dropped to `nobody:nobody`, state
in root-owned `/var/run/c64-harness` and `/var/log/c64-harness`.

Consumers: `tests/rig_ip65_rrnet_hw.py` here, and c64-wireguard, which
also reads the lease file (real RR-Net cartridge in the U64E,
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

`tests/rig_ip65_rrnet_hw.py` reads `HOST_IP`, `C64_IP`, `C64_MAC` and
`TEST_HOST` from the installed up helper via `ip65_hw_checks.rig_const()`,
and `tools/test_ip65_hw_checks_unit.py` checks them against the library's
defaults when the helper is present. They stay plain, unquoted `NAME=value`
lines, one per line (the helper also carries `PIDFILE`, `LEASEFILE`,
`LOGFILE` that way).

## Interface selection

The current script takes the NIC as `$1`. The allowlist takes no
arguments, and BSD names are not stable: they differ between Macs and move
when an adapter is re-plugged (on the current Mac `en4` is Thunderbolt 2,
not an Ethernet adapter). So:

- the adapter is named by its **MAC address**, as a literal
  (`RRNET_NIC_MAC`) in the helper itself rather than the config file the
  first draft proposed: a new adapter means editing that line and a reviewed
  reinstall. The helpers resolve it to an `enX` at run time and refuse to
  start when no interface or more than one carries it;
- never accept it from the caller's environment (`env_reset` drops it
  anyway);
- up writes the resolved name to `/var/run/c64-harness/rrnet.iface`; down
  reads it back, and the rig and the capture use it.

**Which adapter, on the current Mac:** the USB 10/100/1000 LAN adapter
`a0:ce:c8:dd:f4:f9`, en6 on 2026-10-21.

## rig-up must

1. Refuse arguments, non-root and non-Darwin (exit 64 / 77 / 2, as the feth helper).
2. Check the NIC exists and is `status: active`, else fail with "cable
   connected and C64 powered on?" (a CS8900a lights the link only with
   cartridge power). Warn, do not fail, when media is not `10baseT`: an
   RR-Net is 10 Mbps only, so anything faster is probably the wrong NIC.
3. Refuse when any other process is already listening on `10.0.66.1:53`
   (two rigs cannot share the address). DNS only: dnsmasq binds DHCP to
   `*:67` with `SO_REUSEPORT`, which the feth rig's dnsmasq legitimately
   shares.
4. `ipconfig set <NIC> MANUAL 10.0.66.1 255.255.255.0`, not `ifconfig`, so
   the Mac's own DHCP client stops on that link instead of leasing from the
   rig. Skipped when the address is already set.
5. **Truncate the lease file and the log unconditionally**, even when
   dnsmasq is already running. `--log-facility` appends and the lease file
   outlives a restart, so a stale `DHCPACK ... 10.0.66.200` line would
   otherwise read as "the C64 took a lease" with the C64 powered off.
6. Start dnsmasq (flags above) with pid
   `/var/run/c64-harness/rrnet-dnsmasq.pid`, leases
   `/var/run/c64-harness/rrnet-dnsmasq.leases`, log
   `/var/log/c64-harness/rrnet-dnsmasq.log`. **Every up restarts dnsmasq**
   (the first draft said leave a running one alone): a running dnsmasq
   rewrites its in-memory leases into the truncated file, so fresh evidence
   needs a restart. The running instance is identified by `comm` = the
   libexec dnsmasq, `user` = nobody and this rig's `--pid-file` argument,
   not by the pid alone. Fail if the new one does not stay up. Hence the rig
   runs up only when the segment is down, never over a running one.
7. The lease (0644) and log (0664) files stay readable by the invoking
   user. The rig decides nothing from them; c64-wireguard reads the lease
   file.

## rig-down must

1. Stop only the dnsmasq its pidfile names, after the same `comm` + `user`
   check; ignore a malformed pidfile or a symlink.
2. Return the NIC to DHCP addressing (`ipconfig set <NIC> DHCP`).
3. Leave the feth rig (10.0.65.x) untouched.

## Not the helpers' job

- The packet capture. It needs no root: BPF access comes from the
  `access_bpf` group (Wireshark's ChmodBPF, `/dev/bpf*` root:access_bpf
  0660, re-applied at boot), checked 2026-10-21. So the rig runs `tcpdump
  -i <NIC> -n -s0 -U -w …` itself as the user (`-s0` and `-U` are both
  required by `tools/ip65_hw_checks.py`), and no capture helper is needed.
- IP forwarding / NAT: the segment is deliberately isolated.

## Repo-side follow-up (done)

- `tests/rig_ip65_rrnet_hw.py` calls the helpers via `sudo -n` the way
  `tests/rig_vice_https_macos.py` does (up only if the segment is down,
  down only if it brought it up), takes the NIC from `rrnet.iface`
  (`RRNET_IFACE` overrides), and reads `rig_const()` from the installed
  helper.
- `tools/rig-up-rrnet-macos.sh` is deleted; the `sudo bash` lines in
  `tests/rig_ip65_rrnet_hw.py`, `CLAUDE.md` and `tests/README.md` are gone.
