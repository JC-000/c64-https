# #155 phase 2: Phase 0 spike results (2026-09-30, master ac7099d)

> **Archived design record (moved into the tree 2026-10-18).** This is the #155 phase 2 spike folder as it
> stood, kept because code cites it. `DECISIONS.md` is the binding record and settles the "pending"
> list below; `l3/L3-design.md` is the trust-policy design. Paths in these files (`../s1-storage/`,
> `c64-https-wt/p2-*`, `~/Documents/...`) refer to the old out-of-tree layout and no longer exist. Every
> figure is pinned to the master commit its file names; re-measure before reusing one.

UCI only; ip65 is parked. Standing priority: all crypto on the 6510, with the ESP32 offload (M3) as a separate variant.
Every figure is measured unless marked [E] (estimate) or [I] (inferred).

## S1 storage: PoC in ../s1-storage/s1/ (untracked, worktree detached at ac7099d)
- Recommendation: the UCI DOS target, on persistent media (/USB1), never /Temp (a RAM disk, lost at power-off [I]).
- Glue: 325 B as built, ~256 B if the record file stays <=512 B (single-part read).
- Speed at 48 MHz: save ~29 ms, load ~30 ms (/Temp); save ~130 ms, load ~77 ms (/USB1). KERNAL drive 8 takes 2.5-3 s per save, drive-bound.
- Not-found: "FILE DOESN'T EXIST" vs "PATH DOESN'T EXIST" (no medium). Classify on buf[0]=='F' && buf[5]=='D'.
- Hazards:
  - Opening an existing file for write empties it, and nothing is durable until close. A C64 reset mid-replace destroyed the old record.
  - Therefore: write pins.tmp, close, read it back and verify, then DELETE + RENAME ($0A). The loader falls back to .tmp.
  - A single WRITE_DATA stores at most 891 B, not 892.
  - A read error reports a stale "00,OK" [I], so always check the byte count.
  - A handle open across a C64 reset leaks in the firmware [I].
- VICE cannot test the UCI DOS path (no UCI emulation [I]). The harness can drive it on the U64E (load_prg + FTP check).
- Not done: C64U run, the write-verify-rename code, the root cause of the VICE true-drive hang (KERNAL path only).

## S2 memory: reclaim patch in s2/s2-reclaim.diff (5 files, +54/-3)
- Free bytes at ac7099d, pinned: uci-onchip has OVERLAY 1,482 and HOT 450. uci-comb has OVERLAY 92, HOT 79, LOADER 99, NET_CODE 49.
- Feature needs [E]:
  - typed host+path: ~100-150 B code, ~165 B BSS (the runtime plumbing already exists: tls_hostname, http_host_ptr, http_path_ptr);
  - store: 60-150 B;
  - lookup + TOFU/changed UI: ~180-260 B;
  - optional CA-key check glue: ~100-160 B + a 64 B key.
- Verdict: uci / uci-onchip GO today. uci-comb NO-GO as is, GO after reclaims.
- Reclaims, each .ifdef-gated with a re-arm knob; all knobs on reproduces the baseline hash on 5 builds:
  - R1: crypto_swap.o, 204 B NET_CODE. Knob S2_KEEP_CRYPTO_SWAP; test_p384_symbols needs the knob.
  - R2: dead x509_parse_cert + OID table: 573 B LOADER + 36 RODATA + 199 BSS. Knob X509_PARSE_CERT; test_x509 needs it. It CONFLICTS with the CA-key check, which would reuse the parser. ip65 must keep that BSS (the sqtab@$BC00 assert).
  - R3: viewer.s, 1,189 B, unreachable in all shipped products. Gate: HTTPS_BODY_TO_REU / VIEWER_TEST_HELPERS. This alone makes comb fit.
  - R4: dead word32 routines, 272 B HOT. Knob WORD32_ALL.
- VICE smoke on uci-onchip after R1-R4: PASS (x509_name, hs_sequence, finished_verify, tls_deframer, ecdsa_kat_oracle, aead_fail_closed). Comb and ip65 images were not smoked.

## S3 trust design: s3-trust/S3-trust-design.md (+ 43-host survey data)
- Leaf keys rotate at every renewal: 5 of 8 changed within a month, and CT shows no key reuse. So leaf pins in the bundle can only WARN; enforcing bundle entries must be CA (intermediate) keys.
- On-device leaf<-intermediate verify (P-256/SHA-256 issuers only) covers 3 of 16 reachable non-Cloudflare hosts: github, google, youtube. lwn, wikipedia and browserleaks are under Let's Encrypt P-384 (YE1/YE2).
  - It adds ~16.4 s on comb (server silence ~41 s) and ~30 s on onchip (~69 s, fits github only).
  - It must pair with x509_name. There is no clock, so no expiry or revocation check.
- "MAC per CA": a bundle compiled into the PRG needs no MAC; a separate bundle file needs a P-256 signature. An HMAC over the store is only a checksum (the key would sit in the PRG or on the disk, and REST writemem is unauthenticated), so call it a checksum.
- Semantics:
  - precedence: build pin > bundle > TOFU;
  - record only after the server Finished and the name check pass; stage in RAM and write after close;
  - first use only for "valid store, host absent"; any other error fails closed;
  - "accept changed key" re-arms one retry with the exact 32 B hash that was shown.
- Record format:
  - host key: 16 B truncated SHA-256 of the lowercased host;
  - 64 B fixed records;
  - header "C6TS" + version + generation + N;
  - an 8 B SHA-256 trailer.
  - S3 proposed ping-pong TRUST.A/.B slots; S1 measured that write-verify-rename is needed. RECONCILE these in L2/L3.

## Decisions pending with the user (before any build lane starts)
1. Storage: the UCI DOS target on /USB1 (recommended by S1). The configured path must be persistent media.
2. uci-comb: take R3 (viewer gate) at least. Take R2 only if the CA-key check is dropped.
3. CA validation:
   - "packaged = pinned by default" means CA-key pins, which cover only github today, plus warn-only leaf pins.
   - Is the on-device CA-key check (+16-30 s, 3/16 hosts) worth building now?
4. Bundle format: compiled into the PRG (no MAC) vs a separate signed file.

## M3 (secondary; separate BACKEND=uci-m3 variant, after the trust-store work)
- 10 errata (E1-E10) relayed to the 1541ultimate-e5 session 2026-09-30. They are saved there untriaged; rulings come in its next session.
- Client sketch: see m3-client-sketch.md.
