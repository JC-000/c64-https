# M3 client sketch: SECONDARY, separate variant (desk review 2026-09-30, c64-https ac7099d)

The spec is frozen M3-SPEC.md sha256 c265fdfc… under ~/Documents/1541u-esp-tls-archive/session-0929/drafts/, with Appendix A fc064525….
No firmware exists yet. Never test on a device expecting M3, and post nothing upstream until a C64 program works end to end.

## Errata sent to 1541ultimate-e5, awaiting rulings
- E1: the 45/12 s bounds have no start point; a reply wait over 45 s should be the wedge verdict (reset).
- E2: the startup leftover scan needs "ABORT + bit-2 wait" first.
- E3: OPEN_TCP has no bound.
- E4: INFO must be exactly 3 bytes, since a trailing $00 claims every session.
- E5: an early DATA_ACC loses READ bytes like ABORT does [I].
- E6: status 17 is described two ways.
- E7: "do NOT CLOSE" after $FFFF + ": 9".
- E8: no maximum status-line length (our buffer is 16 B; lines run to ~41 B).
- E9: handle range, and whether 0 is legal (we treat 0 as no-socket, #36).
- E10: ready/87/92 transient or not.
- Porting-notes item 7 ("03 25 after boot abort") is superseded by the INFO scan + CLOSE.
- Our status capture keeps the last 2 bytes; the variant needs the first two digits.

## Design
- Build:
  - BACKEND=uci-m3: cfg/c64-https-uci-m3.cfg, src/net/uci-m3/{net.s, net_manifest.s, net_tuning.inc}, plus -I src/net/uci for uci_regs.inc.
  - It drops the 6502 TLS/crypto from the link; $(error) against the NISTCURVES/P384/X25519 flags.
  - Not in PACKAGE_VARIANTS. Gate: the three shipped PRG hashes are unchanged.
- net_abi.inc mapping:
  - net_init: TOD start, ABORT + bounded bit-2 wait, `03 23 FF` detect, leftover scan and CLOSE.
  - net_tcp_connect: OPEN_TLS `03 21`, 45 s wait.
  - net_poll: READ with 12 s wait, decoded as:
    - $0000 + 01/05: gone, no CLOSE (05 = possibly truncated);
    - $0000 + 12/14/16/17: CLOSE;
    - $FFFF + 11: idle;
    - $FFFF + 9: gone, no CLOSE;
    - a partial-reply early exit: CLOSE.
  - net_tcp_close: skip if the handle is gone.
  - http_get_plain must not return C=0 on a timeout.
- Defaults (proposed): trust=BUNDLE, flags bit0=1 (TLS 1.3 only); PIN via a build knob.
- Error codes: allocate in c64-wireguard/src/net_abi.inc first. Reuse $8D/$8E by meaning, new codes from $90.
- Size [E]: 600-800 B of code + ~80 B BSS. It fits only because the crypto is dropped.
- Test before firmware exists: an M3NetworkTarget model on the existing 6502-interpreter harness (test_uci_data_acc CPU, test_uci_timeout_recovery CommandInterface, test_uci_abort_recovery AbortModel), with one mutant per spec rule. VICE can't be used: $DF1B-$DF1F is unmapped.
- Shareable tests:
  - http_body_checks + unit tests; test_body_truncation;
  - the rig_https_banner shape; rig_https_local + listener with a PIN mode; ensure_certs (must-fail 94);
  - test_net_err_registry, flags_stamp, runner_coverage;
  - test_uci_* re-run on the variant PRG;
  - an A/B oracle: same URL, same body length and CRC-32.
