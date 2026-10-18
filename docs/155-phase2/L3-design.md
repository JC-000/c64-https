# L3: trust policy design + sizing (#155 phase 2, UCI)

2026-10-01, master `f20d484` (#260 L0, #262 L4, #261 L1 merged). Design only; implementation follows L5.
Labels: **[M]** measured today on `f20d484`, **[E]** estimate. Binding inputs: DECISIONS.md 3, 4, 7, 8, 10; S3 §4-§6.
**Scope: UCI only.** `TRUST_STORE=1` is `$(error)` on ip65 (no DOS target), so the bundle is UCI-only too. Item 10's ip65 `cert_buf`/nistcurves-BSS union note is moot for L3.

## 1. State machine and precedence (build pin > bundle > TOFU)

There is one resident hook, and it is the only L3 code that runs while a socket is open. It generalises `cert_pin_check`, which `x509_extract_pubkey` already tail-calls, and keeps the #152 interlock (`cert_pin_hs_keys` / `cert_pin_send_finished`). The hook:
- hashes the 91 B SPKI window, exactly as today;
- copies the hash to `tp_got[32]`;
- compares it against `tp_expect` (a pointer, or none) and `tb_spki` (advisory);
- sets `tp_status`;
- tail-calls `x509_verify_hostname`.

Everything else runs **before `net_tcp_connect` or after `net_tcp_close`**. On comb that means the cold bank (§4). Nothing reads the keyboard between connect and close.

**Per 'G', in `do_https_get`:**

1. **Before connect** (`trust_pre`):
   1. `https_target_prompt` (L1) produces `tls_hostname`, lowercased, trailing dot refused. That matches L4's host key with nothing more to do.
   2. Clear the one-shot override unless `tp_ovr_key == SHA-256(host)[0:16]`. It is consumed by this attempt either way.
   3. **Build pin.** If `HTTPS_PIN_SPKI` is set and `tls_hostname == http_host_target`, then `tp_expect = cert_pin_expected` and the mode is ENFORCE, or WARN under `HTTPS_PIN_WARN`. **Skip the store and the bundle entirely.** Never record. (See Q2.)
   4. Otherwise, `trust_store_load(tls_hostname)`:
      - **FAIL** (any reason): print `TRUST FAIL nn <TAG>` and `NOT DIALLED`, then return. Fail closed; no socket is opened. The tags are NOMEDIUM(02), DOS(03), READ(04), VERSION(06), TIE(08), CHANGED(11), BUSY(09: a bug).
      - **EMPTY**: print `TRUST STORE EMPTY`, on every GET, so that deletion stays visible. Continue as first use.
      - **VALID, and `trust_store_lookup` hits:** `tp_expect = ts_rec+16`, mode ENFORCE. `ts_rec` is resident BSS and survives the connection.
      - **VALID, and the lookup misses:** first use. `tp_expect` = none, mode FIRSTUSE.
   5. **Bundle** (§2), run after the store load because it reuses the ring and `ts_key`. On success with a hit, `tb_spki = rec+16` and `tb_found = 1`. Any bundle failure prints its line and sets `tb_found = 0`. A bad bundle never blocks a connection, because its pins are warn-only (item 3).
2. **In the handshake** (the hook, at Certificate, before CertificateVerify):

   | mode | got == expect | got != expect |
   |---|---|---|
   | ENFORCE (store) | MATCH, continue | if override armed and got == `tp_override` (all 32 B): ACCEPT, continue; else MISMATCH: print `KEY CHANGED EXP xxxxxxxx GOT yyyyyyyy`, C=1 abort (no client Finished) |
   | ENFORCE (build pin) | MATCH | `PIN FAIL …`, abort, exactly as today |
   | FIRSTUSE | n/a | FIRSTUSE, continue |

   - **Bundle advisory, in any non-build-pin mode:** if `tb_found` and got != `tb_spki`, print `BUNDLE WARN EXP … GOT …` and set `tp_bwarn`. It never aborts.
   - **The interlock is unchanged:** client Finished goes out only if the hook ran this connection and did not reject.
3. **After the handshake.** When `tls_connect` returns C=0, the server Finished is verified and the name check has passed, because the name check is the hook's own tail. Set `tp_pending = 1` iff the status is FIRSTUSE or ACCEPT. **Nothing is staged yet:** staging is cold code on comb.
4. **After close.** All exits of `do_https_get` after the dial are funnelled through one `@finish`: `net_tcp_close`, then `trust_post`.
   - **Pending**, from FIRSTUSE or ACCEPT: build the record in `ts_rec`:
     - SPKI = `tp_got`;
     - mode = TOFU `$01` or ACCEPTED `$02`;
     - flags bit 1 = bundle corroborated;
     - uses = 0;
     - display = the first 12 bytes of the host.

     Then call `trust_store_stage(ts_rec)` and `trust_store_save`. The host key is forced to `ts_key` from *this attempt's* load. Print `KEY RECORDED xxxxxxxx`, `TRUST STORE FULL`, or `TRUST SAVE FAIL nn`. FULL means no eviction.
   - **Exception, FIRSTUSE with `tp_bwarn`:** don't auto-record. Ask instead (Q3).
   - **MATCH:** no write. Don't bump the use count, because one save per connection is wear and time.
   - **MISMATCH:**
     1. Print the whole GOT hash: 64 hex digits on 2 lines. Comparing only 32 bits is grindable.
     2. Flush `$C6`, then show `A=ACCEPT ON RETRY  OTHER KEY=REFUSE`.
     3. On **A**, set `tp_override = tp_got` (32 B) and `tp_ovr_key = ts_key` (16 B), then print `ACCEPT ARMED: G, SAME HOST`.
     4. On a retry where got != `tp_override`, print `ACCEPTED KEY NOT SEEN` and abort. The override is already cleared.
   - **Store state:** `stage` consumes the load, and every save leaves it NONE. The next GET reloads (step 1.4), so a stale lookup is never reused.

## 2. Bundle

- **File:** `$(TRUST_STORE_DIR)/TRUST.P`. It reuses `ts_set_name`'s letter slot. If the file is absent, print `NO BUNDLE` once per boot and carry on.
- **Load:** read it into the TCP ring at `$C000` with the same `dos_open`/`dos_read` path L2 uses. Read at most 2,120 B + 1, so an oversize file shows. This happens before connect: the store image is already consumed into `ts_rec`, and the ring is free (`ts_guard`). **It never touches `cert_buf`**, so the comb cold code that lives there and the ip65 union are both irrelevant.
- **Verify order** (item 10):
  1. **Structure.** Magic `C6TB`, version `$01`, N ≤ 32, size == 8+64N+64, keys strictly ascending, each record mode `$10`, flags `$01`, uses 0. Failure prints `BUNDLE BAD FORMAT`.
  2. **Signature.** `tls_transcript_init/update/hash` over header‖records, then:
     - copy the digest to `ecdsa_hash`;
     - copy the trailer (r‖s) to `ecdsa_sig_r`;
     - copy `TRUST_BUNDLE_PUBKEY_BYTES` to `ecdsa_pubkey_x/y`;
     - set `ecdsa_curve_id = 0`, then `jsr ecdsa_verify`. The dispatcher gets VIC blanking, about 6% faster [M-prior].

     Failure prints `BUNDLE BAD SIGNATURE`.
  3. **Generation floor.** Unsigned `gen >= TRUST_BUNDLE_GEN_FLOOR`. Failure prints `BUNDLE OLD GEN`.

  Then look up `ts_key` linearly and copy the 32 B SPKI to `tb_spki`.
- **SHA-256 without clobbering the transcript:** every bundle and store hash runs before connect. `tls_send_client_hello` calls `tls_transcript_init` (`tls13.s:420`), so no handshake state is live and none is inherited. The `ecdsa_*` 160 B struct is also dead before connect; CertificateVerify rewrites it.
- **Cache: verify once per boot.** Keep `tb_digest[32]` (the verified e) and `tb_ok` resident. On later GETs, reload the file and re-hash it. If e == `tb_digest`, skip ECDSA; the floor is re-checked because it is cheap.
  - **What it costs:** one 2 KB DOS read plus about 33 SHA-256 blocks per GET. That is tens of ms at 48 MHz [E].
  - **What it saves:** a 16.4 s (comb) or 28-30 s (onchip) [M-prior] ECDSA on every GET after the first.
  - Re-hashing means a bundle swapped on disk mid-session is caught. The digest is not a cache key the attacker controls: e is recomputed from the bytes.
  - **When:** lazily, at the first 'G' that finds `TRUST.P`. The screen shows `VERIFYING BUNDLE…` because the step is long. Never at boot (Q4).
- **Replay:** the floor blocks bundles older than the PRG's floor. An older bundle that is still at or above the floor is accepted. That is acceptable for warn-only pins. Persisting the highest generation seen into the store is deferred.

## 3. Packaging guard

- **Knob:** `TRUST_BUNDLE=1`, separate from `TRUST_STORE` (the bundle needs the store's DOS code and `ts_key`). It is UCI-only.
- **Key source:** `TRUST_BUNDLE_KEY_INC ?= tools/trust_bundle_TEST_ONLY_pubkey.inc`. The Makefile copies it to `build/trust_key.inc`, content-compared like `https_host.inc`, so changing the key or the floor rebuilds exactly `trust_bundle.o`.
- **Release flag:** `make package` passes `TRUST_RELEASE=1`, which becomes `-D TRUST_RELEASE=1` and so is stamped.
- **Guard, in three layers:**
  1. **Source.** `trust_bundle.s` carries `.assert .not (.defined(TRUST_RELEASE) .and TRUST_BUNDLE_KEY_IS_TEST_ONLY), error, "TEST-ONLY bundle key in a release build"`.
  2. **Makefile.** Under `TRUST_RELEASE=1`, a parse-time `$(error)` fires if the chosen `.inc`'s 64 key bytes equal the test `.inc`'s. That catches a hand-edited `IS_TEST_ONLY = 0` on the test key.
  3. **Manifest.** `write_manifest.sh` records the key's SPKI SHA-256 line from the `.inc`, and `package-verify` refuses the test key's `e8648ff4…`.
- **Production key:** the maintainer runs `trust_bundle.py inc --key <prod.pem> --floor N -o <outside-repo>/prod_key.inc` and builds with `TRUST_BUNDLE_KEY_INC=` that path.
  - Only the **public** key and the floor enter the build; the private key never touches `make`.
  - Committing the `.inc` would be harmless, because it is public. The guard does not depend on its location.
  - Bump the floor at each release that re-signs.

## 4. Sizing

Measured free bytes (`tools/measure_margins.py`, hand-built per profile, `TRUST_STORE=1`, reclaims at their defaults) [M]:

| profile (PRG sha256) | LOADER | NET_CODE | NET_BSS_TAIL | CRYPTO_OVERLAY | CRYPTO_HOT |
|---|---|---|---|---|---|
| uci, REU, not shipped (`33c15e51`) | 796 | 253 | 63 | 1,339 | 714 |
| **uci-onchip** (`44240b5f`) | 796 | 261 | 63 | 1,242 | 758 |
| **uci-comb** (`2dd1168a`) | 345 | 253 | 63 | 211 | 453 |
| **comb Wikipedia demo** (`HTTPS_BODY_TO_REU=1`) | — | — | — | — | **link FAILS: `LIB_NISTCURVES_P256_CODE` overflows CRYPTO_HOT by 736 B** |
| same demo without `TRUST_STORE` (`61333a5c`) | 329 | 253 | 43 | 277 | 455 |

**The store today [M]:**
- `TRUST_STORE_CODE` is **1,191 B** (`$4A7`, store + `uci_dos`). L2 quoted 1,185.
- `TRUST_STORE_BSS` is 108 B.
- On onchip both sit in CRYPTO_OVERLAY. On comb the code sits in CRYPTO_HOT and the BSS in OVERLAY.

**The existing pin [M]:** `CERT_PIN_CODE` 104 B + `CERT_PIN_UI` 191 B (including the 32 B pin) = 295 B.

**L3's own bytes [E]:**

| part | code | BSS | where |
|---|---|---|---|
| Resident hook (generalised `cert_pin_*` + selection + override compare + bundle warn) | ~400 | ~150 (`tp_got` 32, `tb_spki` 32, `tp_override` 32, `tp_ovr_key` 16, `tb_digest` 32, flags) | must be resident on every profile. Under `TRUST_STORE=1` it replaces `cert_pin.s`'s 263 B of code rather than adding to it. |
| `trust_pre` + `trust_post` (store driver, prompts, record build) | ~550 | 0 | cold unit **U_TS**, together with `TRUST_STORE_CODE`: 1,191 + 550 ≈ **1,750 B ≤ 2,048** (`cert_buf`) |
| Bundle (load, structure, hash, verify driver, floor, lookup) | ~400 | 0 | cold unit **U_TB** |
| Strings + pubkey 64 | ~300 | 0 | split across U_TS and U_TB |
| **Total** | **~1,650** | **~150** | |

**Verdict per profile:**
- **uci-onchip fits without a REU [E].** Hook → CRYPTO_HOT (758). BSS + policy + bundle (~1,100) → CRYPTO_OVERLAY (1,242) with the overflow strings → LOADER (796). That leaves about 1.3 KB scattered. The largest single block, OVERLAY at 1,242 B, is the constraint, so the cold-candidate code needs two segments, as `cert_pin` already does.
- **uci (REU profile, not shipped):** same as onchip, with about 100 B more slack.
- **uci-comb needs L5.** It has 1,325 B free in total [M], against the ~1,650 [E] that L3 adds. Once L5 moves `TRUST_STORE_CODE` cold, CRYPTO_HOT is about 1,644 B free [E from M]. The resident hook + BSS (~550) then fits with about 1 KB spare [E]. U_TS and U_TB are each under 2,048 B.
- **comb Wikipedia demo needs L5.** It is 736 B over today [M]. After L5 moves the store cold, the free space returns to about 1,250 B total [E from M]: HOT 455, LOADER 329, NET_CODE 253, OVERLAY 169, NET_BSS_TAIL 43. The resident ~550 then fits with **about 700 B spare [E]**, provided the hook is split HOT/LOADER and the BSS goes into OVERLAY. That is tight: re-measure after L5.
- **No option beyond L5 is needed.** Further reclaims, cold-loading from `/USB1` (S4 advised against it) and requiring a REU on onchip are all unnecessary. If the demo still misses after L5, the next lever is to put `tb_digest`/`tb_spki` in the REU on comb, worth 64 B.

**Item 8 rule this design relies on:** the cold units are called only from `trust_pre`/`trust_post`. Both run with no socket, and L5's swap must refuse while `net_tcp_state == CONNECTED`. The hook and its BSS are never cold.

## 5. Test plan (every PR shows red then green; each check gets a mutation)

**Three kinds of test:**
- **INTERP:** the 6502 interpreter + UCI DOS model behind `tools/test_trust_store_6502.py`. It has no hardware and runs the shipped bytes. Each case:
  - pokes a 91 B SPKI window and calls the hook;
  - stubs `ecdsa_verify_256`'s result;
  - asserts on the DOS traffic and the commands sent to the socket.
- **VICE:** real `ecdsa_verify_256` with the bundle poked into `$C000` and the verify entry called directly. It extends `test_trust_bundle_c64.py`, which has no DOS.
- **U64E:** real `/USB1` + `tools/https_e2e` listener with switchable certificates, via the harness queue (run-the-rigs order).

| behaviour / negative | INTERP | VICE | U64E |
|---|---|---|---|
| First use (EMPTY and VALID-miss): records TOFU with `SHA(typed host)` and `tp_got`; host-side `trust_store.py` dump matches byte for byte | ✓ | | ✓ |
| Match: proceeds, **no** DOS write (generation unchanged) | ✓ | | ✓ |
| **Changed key without accept is refused:** no client Finished (listener sees none, `tls_last_state`), no GET, store generation unchanged | ✓ | | ✓ |
| **Accept records only the shown hash:** arm on K2; retry with K3 refused and override cleared; retry with K2 records ACCEPTED/K2 exactly; a third attempt with no re-arm and K3 is refused | ✓ | | ✓ |
| **Typed host mismatch never records:** arm for A, next attempt types B → override discarded, nothing recorded for A or B; L1-refused host → no load, no save, no dial | ✓ | | ✓ (A/B) |
| **Delete the store → `TRUST STORE EMPTY`** on every GET, then first use | ✓ | | ✓ |
| Every FAIL reason → `TRUST FAIL nn`, **no TCP_CONNECT issued** | ✓ | | NOMEDIUM only |
| **Tampered bundle:** a flipped record byte or a flipped r/s → BAD SIGNATURE; bad magic, size, N=33 or unsorted → BAD FORMAT; `tb_found = 0`, connection unaffected | struct | sig ✓ | one case |
| **Replayed bundle:** validly signed gen < floor → OLD GEN; gen == floor accepted | ✓ | ✓ | |
| Bundle cache: second GET skips ECDSA (cycle count); file swapped on disk → re-verified | ✓ | | ✓ (wall-clock) |
| Bundle warn: TOFU match + bundle mismatch → `BUNDLE WARN`, proceeds, no write | ✓ | | ✓ |
| Build pin for its host skips the store (no DOS traffic); other host → TOFU | ✓ | | |
| Never blocks mid-handshake: no GETIN/`$C6` reads between connect and close (counted); the cold swap refuses while CONNECTED | ✓ | | |
| Torn save during `trust_post` (reset mid-write) → older slot wins | (L2 has it) | | L2 |
| Packaging: `make package` with the test key → non-zero; test bytes with a hand-set `IS_TEST_ONLY=0` → non-zero; throwaway non-test `.inc` in `$TMPDIR` → passes | host-only (no VICE) | | |

- **Hardware-only:** real UCI DOS timing, the `/USB1` medium, and handshake silence. The pre/post work must add **0 s** to server-perceived silence; measure it against the W0 figure.
- **Mutation coverage:** each security negative has a mutation that must turn its test red. Candidates: drop the override compare, compare 4 B instead of 32, skip the floor, record on MISMATCH, ignore `tp_ovr_key`.

## 6. Open questions for the user (each with a recommendation)

1. **Ship it in packages?** **Rec:** `TRUST_STORE=1` on uci-onchip and uci-comb once L5 lands. `TRUST_BUNDLE=1` waits until you create a production key; until then packages build without the bundle rather than block a release.
2. **Build pin scope under typed targets.** **Rec:** bind the pin to `HTTPS_HOST` only (S3 §4.1's "for its host"), so other typed hosts use bundle/TOFU. Today a pinned build enforces the pin on every typed host, which means it can only reach that host.
3. **First use when the bundle leaf disagrees.** **Rec:** proceed (warn-only), but don't auto-record. After close, ask `RECORD KEY? A=YES`; the key has already passed CertificateVerify and Finished, so no retry is needed. The alternatives are auto-record, or treating it like a mismatch.
4. **Bundle verify timing.** **Rec:** lazily at the first 'G', once per boot, with the digest cached as in §2. Verifying at boot adds 16-30 s to every boot; verifying every connection adds it to every GET.
5. **No medium / store FAIL refuses every GET (S3 §4.3).** **Rec:** keep it strictly fail-closed, with no "continue unpinned" key. The message names the reason; deleting both slots (→ EMPTY, which is visible) is the explicit way to reset.
