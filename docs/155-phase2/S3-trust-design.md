# S3: in-C64 trust design for #155 phase 2 (UCI)

2026-09-30, master `ac7099d`. Labels: **[M]** measured today, **[M-prior]** measured earlier (source named), **[I]** inferred. Everything here runs on the 6510. The ESP32 TLS offload is not used anywhere.
Raw data is in `data/`: `survey_2026-09-30.jsonl` (43 hosts), `ct_history.txt` (CT via certspotter), and `survey.py`.
Vantage: this Mac, with Cloudflare WARP in full-tunnel mode (egress DFW). WARP is not intercepting TLS: all 39 chains that came back verify against the system store, each under its public CA **[M]**. Edge-dependent answers may differ from other locations.

## 1. What "MAC-based CA validation" can mean

A MAC cannot verify a CA signature, because it needs a secret shared with the signer. There are two realistic readings.

- **(i) Validate chains on a trusted host at packaging time and ship integrity-protected pins.** This is sound, and it is how the bundle gets built: a host tool validates each target against the OS/Mozilla store, then emits leaf SPKI hashes and P-256 intermediate keys. Which integrity primitive to use depends on where the bundle lives:
  - **Bundle compiled into the PRG:** needs no MAC at all. Anyone who can alter the bundle can also alter the code, so the bundle's integrity is the release's integrity (the MANIFEST sha256).
  - **Bundle shipped as a separate file** (refresh without a new PRG): needs an **ECDSA P-256 signature, not a MAC**. The public key sits in the PRG, the maintainer holds the private key, and `ecdsa_verify_256` checks it. A MAC key in a public PRG is a published key, so anyone could forge the bundle. Checking the signature costs one verify per boot: 16.4 s (comb) or 30.5 s (onchip) at 48 MHz **[M-prior]**, or about 24 min for ip65 at 1 MHz **[M-prior]**.
- **(ii) HMAC over the on-device TOFU store.** What it buys depends on where the key lives:
  - **Key compiled into the PRG, or kept on the same disk:** equivalent to a checksum. It catches torn writes and bit rot, and nothing more.
  - **Key derived from a passphrase typed at boot:** stops offline edits of the store. But on UCI the realistic tamperer is a LAN host that can reach the Ultimate's REST/FTP. The device serves `writemem`/`run_prg` over REST, which the rigs use every day with no credential, and such an attacker can patch live code instead. I did not measure whether a firmware network password closes that. So a passphrase HMAC buys little on these devices. **Decision: SHA-256 checksum only**, reusing the linked code. Call it a checksum and never a MAC.

**The closest in-C64 meaning of "validate the CA" is §2:** the 6510 itself verifies the leaf's signature under a pinned intermediate key.

## 2. On-device leaf←intermediate verification: measured coverage

The survey fetched each host using the client's exact offer: TLS 1.3, ChaCha20, X25519 only, and `-sigalgs ECDSA+SHA256`. A host counts as reachable if the handshake completes with a P-256 leaf and CertificateVerify scheme 0x0403 **[M]**.

| result | hosts |
|---|---|
| **Covered:** leaf signed with ecdsa-with-SHA256 under a P-256 intermediate (7) | github.com (Sectigo DV E36); www.google.com and www.youtube.com (GTS WE2); ietf.org, www.cloudflare.com and lemon64.com (GTS WE1); example.com (Cloudflare/SSL.com ECC CA 3) |
| Not covered: P-384 intermediate, leaf signed with SHA-384 (11) | lwn.net, en.wikipedia.org, www.wikipedia.org, browserleaks.com, letsencrypt.org, sourceforge.net (LE YE2); news.ycombinator.com, stackoverflow.com, kernel.org, slashdot.org (LE YE1); www.netflix.com (DigiCert G3) |
| Not covered: RSA intermediate over a P-256 leaf (2) | www.facebook.com, www.instagram.com |
| Unreachable by this client at all (23) | 18 have RSA leaves (amazon, microsoft, apple, reddit, x.com, linkedin, bbc, nytimes, guardian, archive.org, mozilla, python, pypi, debian, duckduckgo, gitlab, developer.mozilla, gnu); bing refused the offer (no handshake, though it has a P-256 leaf); 4 are TLS 1.2 only (eff, c64-wiki, csdb, arstechnica) |

- **Coverage:** 7 of 20 reachable hosts (35%), or 7 of 43 surveyed (16%) **[M]**.
- **Coverage after dropping Cloudflare-fronted hosts:** four of the seven are behind Cloudflare (`server: cloudflare` **[M]**), which CLAUDE.md puts out of scope because of its 15 s deadline. That leaves **3 of 16 (github, google, youtube)**.
- **The project's own four targets:** only github is covered. Let's Encrypt's current ECDSA intermediates are all P-384.
- **SHA-384 alone buys nothing:** all 11 SHA-384-signed leaves in the sample sit under P-384 keys **[M]**.
- **Bundle size:** 4 intermediate keys cover all 7 covered hosts, at 64 B each plus an 8 B AKI tag, about **288 B** **[I]**.
- **Intermediate lifetimes:** not_after runs from 2029-02 (GTS) to 2036 (Sectigo) **[M]**. This is certificate expiry, not how long the CA keeps issuing from a key, and I did not measure the latter.
- **The CA itself can change:** CT shows github.com issued by both Sectigo and Let's Encrypt in Aug 2026 **[M]**. A single-intermediate pin can fall off coverage without anything expiring.

**Cost [I from M-prior figures]:**
- One extra verify: +16.4 s on comb or +30.5 s on onchip at 48 MHz. SHA-256 over a 0.8-1.5 KB TBS is negligible.
- Server-perceived silence on comb is 24.7 s today (W0) **[M-prior]**, so about **41 s** with the extra verify. Onchip goes from about 39 s to about 69 s.
- Measured patience is 90 s for github and 45 s for browserleaks **[M-prior]**. Comb fits both; onchip fits github only. Google's and YouTube's patience is unmeasured.

**Mechanics [I, from source]:**
- The leaf is already whole in `cert_buf` (2 KB on UCI) when the deframer calls `tls_cert_stream_finish`. The intermediate on the wire never needs parsing, because its key comes from the bundle.
- Work to add:
  - hash the TBS;
  - parse the leaf's signatureValue (reusing `ecdsa_parse_der_sig`);
  - select the intermediate by AKI;
  - verify;
  - re-extract the leaf key, since the verify overwrites `ecdsa_pubkey_x/y`.
- Estimated code: a few hundred bytes. It fits in the ~1.5 KB free on uci and uci-onchip. It does not fit uci-comb (92 B OVERLAY + 79 B HOT, #155), which is S2's problem.
- **It must be paired with the SAN check (`x509_name.s`, UCI-only).** Without the SAN check, a GTS certificate for the attacker's own domain passes. So this lane is UCI-only, and on ip65 it is worthless.
- **No clock, so no expiry or revocation checks.** An expired or revoked leaf from a bundled intermediate stays valid forever [I].
- **Decision: use it only at first use and on key rotation**, never on every connection (§4).

## 3. Leaf key rotation: re-capture one month after the baseline

| host | 2026-08-30 → 2026-09-30 | current not_after |
|---|---|---|
| github.com, www.google.com, ietf.org, example.com, news.ycombinator.com | **ROTATED**. All five renewed early, with a fresh key. | 11-29, 12-11, 12-17, 12-25, 12-19 |
| en.wikipedia.org, lwn.net, browserleaks.com | same key, same cert (not renewed yet) | 11-03, 11-27, 11-04 |

- **In one month, 5 of 5 renewals changed the key; 0 of 5 kept it** **[M]**.
- **CT history (certspotter):** across 10 hosts with history, consecutive issuances sharing a key: **0** **[M]**. Two hosts returned no CT data.
- **Many concurrent certificates:** google.com has 80 distinct keys and ietf.org 82. Six connections per host from this vantage all saw one key **[M]**, so other edges probably serve other keys **[I]**.
- **This corrects the baseline memory's "browserleaks reuses its key":** certspotter now lists 2 issuances with 2 keys. The earlier "each seen twice" was most likely precert/cert pairs **[I]**.
- **Policy consequence:**
  - A leaf pin shipped in a bundle goes stale within about 60 days for every host measured.
  - **Bundle leaf pins are warn-only.**
  - **Enforcing bundle entries must be intermediate keys (§2).**
  - A build pin (`HTTPS_PIN_SPKI_SHA256`) stays enforce-by-default, but only for a deliberate build aimed at one host.

## 4. Semantics (decisions)

1. **Precedence: build pin > bundle > TOFU.**
   - A build pin disables store lookup for its host.
   - A bundle intermediate entry cannot be overridden by the store.
   - A bundle leaf entry is advisory: a mismatch goes to the accept flow with a louder "BUNDLE" tag.
2. **Record only after the server Finished verifies** (CertificateVerify proves possession of the key; Finished binds the transcript). On UCI, the name check must also have passed. Stage the new record in RAM and write it to disk after `tcp_close`. Writing to disk mid-handshake would eat into the server's patience.
3. **First use is exactly one state:** the store loaded and validated, and the host is absent from it. Everything else fails closed:
   - checksum failure on both slots;
   - a DOS error other than 62 FILE NOT FOUND;
   - an unknown version;
   - a device not present.
   - Both slots returning 62 means "empty store". It is allowed, but the banner says `TRUST STORE EMPTY` so that deletion by an attacker is visible. Bundle and build pins still apply, because they live in the PRG.
4. **CA-assisted TOFU:** at first use or on rotation, if the leaf's AKI names a bundled intermediate and leaf←int verifies (plus SAN), record automatically. Otherwise show `NEW KEY host xxxxxxxx` and ask. This narrows the window for an on-path attacker at first use, for covered hosts only.
5. **Accepting a new key:**
   - On a mismatch, abort. Never block mid-handshake for input: patience is 45-90 s.
   - Show `KEY CHANGED EXP xxxxxxxx GOT yyyyyyyy` (the existing `cert_pin_report`) and offer "(A)ccept on retry".
   - Accept arms a one-shot RAM override holding the full 32 B **GOT** hash.
   - The retry records only if the key presented equals that hash, so the user accepts the key they saw, not whatever arrives next.
   - The override clears after one attempt.
6. **Bundle refresh:** ships as a new PRG release, reusing the existing `make package` / MANIFEST integrity. A separate signed bundle file is optional, and only worth it if releases are too slow; it costs one verify per boot (§1).

## 5. Record format (decisions; medium-agnostic, S1 picks the medium)

- **Host key: 16 B, the truncated SHA-256 of the lowercased host.**
  - The attack to defeat is a TOFU second preimage. The attacker registers a label (free under any domain they own) whose hash equals the victim's, gets it visited first, and their key is then served for the victim.
  - With a *k*-bit key that costs 2^k hashes. 32 bits is trivial. 64 bits is about 1.8×10^19, which is weeks for a GPU cluster **[I]**. **128 bits** is out of reach.
  - Full names would work too, but make records variable-length.
- **Record, 64 B fixed:**
  - host key: 16
  - SPKI SHA-256: 32
  - mode: 1 (`TOFU` / `ACCEPTED` / `OVERRIDE`)
  - flags: 1
  - use count: 2
  - display prefix: 12 (non-authoritative, for a trust-list screen)
- **File:**
  - header: magic `C6TS` 4, version 1, generation 2, N 1
  - N records
  - trailer: SHA-256(header‖records) truncated to 8 B
  - With N ≤ 32 that is 2,064 B **[I]**.
- **Torn writes: ping-pong slots `TRUST.A` / `TRUST.B`.**
  - Load both, validate each, and take the valid slot with the higher generation (serial comparison).
  - Save to the *other* slot (scratch it, then write). A torn write only ever damages the older copy.
  - Never use `@0:` save-replace, because of the 1541 save-with-replace bug.
- **The "no pin stored" state** is the absence of the host key in a valid store (§4.3). There is no sentinel value inside a record.

## 6. Threat model

| mechanism | on-path at first use | on-path later | disk / LAN tamper | stale bundle |
|---|---|---|---|---|
| Build pin (PRG) | stops | stops | n/a (PRG integrity) | n/a; the build goes stale on rotation (fails closed) |
| Bundle intermediate + on-C64 verify + SAN (UCI) | **stops** (7/20 hosts) | stops | n/a | intermediate retired → accept flow; no expiry check |
| Bundle leaf pin (warn) | warns only | warns only | n/a | stale in ≤60 days (§3) |
| TOFU store | **does not stop** | stops, until the user accepts | a checksum does not stop it; deletion resets to first use (banner shows it) | n/a |
| Store checksum / compiled-key HMAC | — | — | detects corruption only | — |
| Passphrase HMAC | — | — | stops offline edits; moot while the Ultimate's REST accepts `writemem` | — |
| Signed bundle file (P-256) | — | — | stops bundle forgery | a replay of an old bundle needs a generation floor in the PRG |

**Residuals under every mechanism:**
- no expiry or revocation checks (no trusted clock);
- ip65 gets no name check and so no chain lane;
- mis-issuance by a bundled intermediate for the victim's name passes.
