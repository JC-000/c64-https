# #155 phase 2: user decisions (2026-09-30)

These are binding for every lane. If the tree contradicts one, report it to the supervisor. Do not work around it.

1. **Storage:** the UCI DOS target on `/USB1` (persistent media). Never `/Temp`.
2. **P-384 stays closed for now.** It will be reopened later, so every reclaim is knob-gated with a re-arm switch, never deleted.
3. **No on-device CA-key (leaf<-intermediate) check in this phase.** Wikipedia (the demo) is covered by trust-on-first-use (TOFU) plus the name check. The bundle carries warn-only leaf pins.
   - Consequence: reclaim R2 (`x509_parse_cert`) is taken.
4. **Bundle:** a separate, SIGNED file. It can be loaded from disk, or into the REU on REU profiles to save RAM.
   - Signature: P-256 ECDSA-SHA256, verified on the C64 with the existing `ecdsa_verify_256`.
   - The public key and a generation floor (anti-replay) are compiled into the PRG.
   - The tree holds a test-only key, labelled as such. The production key is the user's call; do not generate one.
5. **Comb memory:** take R1, R2, R3 and R4 from `s2/s2-reclaim.diff`. R3 does NOT help the Wikipedia demo build (`HTTPS_BODY_TO_REU=1` re-arms the viewer), so size against that build too.
6. **Torn writes (S1 vs S3):** use S3's ping-pong `TRUST.A` / `TRUST.B` slots, plus S1's read-back verify after close.
   - Opening a file for write empties it, so a torn write only ever damages the older slot. No rename is needed.
   - L2 confirms this on hardware.
7. **Semantics and record format:** exactly S3 §4 and §5 (`s3-trust/S3-trust-design.md`), except where 3 and 4 above override them.
   - §4.4 (CA-assisted TOFU) is out of scope.
   - §4.6 is replaced by 4 above.
8. **UPDATE 2026-09-30 (supervisor):** S4's trigger has fired. The Wikipedia demo build on comb does not fit the trust store even with L0: it needs about 1,300 B contiguous and the largest free block is 455 B. A lane after L0 and L2 merge builds a generic cold-code bank for comb:
   - cold code (store, typed-host UI, trust prompts) is kept in the REU;
   - on each call it is DMA'd into cert_buf, but only while no connection is open;
   - REU placement: bank 3, or bank 2 at `$4000` and above. Never `reu_layout`'s `$20100` / `$22100`, which overlap comb's Lim-Lee table.
   - onchip keeps the code resident, because it fits there.
   - From L2: the `TRUST_STORE_CODE` segment (1,185 B) is self-contained, and its state lives separately in `TRUST_STORE_BSS`. The segment uses self-modifying code and addresses its own data absolutely, so it must be LINKED with `run = cert_buf` and `load = the REU image`, not copied after linking. `rig_trust_store` and the 6502 test poke internal labels and will need updating.
   Original item 8 follows.
10. **Inputs for L3 from L4 (PR #262; unconfirmed until #262 clears review):**
    - **Bundle format v1:** an 8 B header (`C6TB`, version `$01`, generation as u16 little-endian, N from 0 to 32), then N × 64 B records sorted by host key, then a 64 B r‖s trailer (big-endian) over SHA-256(header‖records).
    - **C64 verify:** copy the trailer to `ecdsa_sig_r`, the digest to `ecdsa_hash` and the `.inc` public key to `ecdsa_pubkey_x/_y`, then `jsr ecdsa_verify_256`. C=0 means valid.
    - **Mode split:** `$10` marks a bundle leaf pin, warn-only with flags `$01`. `$01`-`$0F` are left to the TOFU store.
    - **Host key:** hash the ASCII host with only A-Z lowercased, never PETSCII. Do not strip a trailing dot; check this against L1's validator.
    - **Shared SHA-256:** the only multi-block SHA-256 is `tls_transcript_*`, so borrow it only outside a handshake.
    - **Buffers:** on comb, cold code occupies `cert_buf`, so the bundle needs another buffer. On ip65, hash the bundle and copy the trailer out before the verify, because `cert_buf` is unioned with the nistcurves BSS.
    - **Check order:** structure, then signature, then generation floor.
    - **Packaging guard (from adv-l4):** L3 must make `make package` fail if the bundle public key in a package build is the TEST-ONLY key, i.e. assert `TRUST_BUNDLE_KEY_IS_TEST_ONLY=0`.
    - **Generation floor:** enforced host-side only so far. Enforcing it on the C64 is L3's job.
11. **L3 answers (user, 2026-10-01).** They answer the open questions in `l3/L3-design.md` §6.
    - **Q1, packaging:** turn on `TRUST_STORE=1` in the uci-onchip and uci-comb packages. The bundle stays out of packages until the user creates a production key, so a release never blocks on it.
    - **Q2, build-time pin scope:** the pin applies ONLY when the typed host equals `HTTPS_HOST`. Other typed hosts go to the bundle, then trust-on-first-use.
    - **Q3, first-use bundle mismatch:** show `BUNDLE MISMATCH`, finish the fetch, and after close ask `RECORD KEY? A=YES`.
    - **Q4, bundle verify timing:** verify lazily at the first 'G', once per boot, and cache the digest. Later fetches re-hash the file and compare.
    - **Q5, override (the user's choice, against the design recommendation):**
      - **When it's offered:** a per-fetch `CONTINUE UNPINNED? Y/N` key, offered on any store failure (no medium, unreadable or corrupt store) AND on a changed key for a trust-on-first-use host.
      - **Build pin:** the override never bypasses an enforcing build-time pin. Warn-only builds already exist (`HTTPS_PIN_WARN=1`). This is a supervisor interpretation; the user was told it can be changed.
      - **Never records:** the override never records the new key. Recording happens only through the accept-exact-hash flow.
      - **Banner:** every overridden fetch shows a persistent UNPINNED banner.
      - **Scope:** it applies to that one fetch only, with nothing sticky.
9. **Future work (the S4 spike studies it, nobody builds it):** keep crypto code that is not running banked out in the REU and swap it in on demand. The crypto libraries are vendored as submodules.
