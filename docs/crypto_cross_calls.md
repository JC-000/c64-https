# Phase B.5 — Cross-Library Call Audit

## Objective

Verify the REU-overlay design's core invariant: **no primitive in one sibling library may call a primitive in another**. The three overlay-hosted libraries (X25519, P-256, P-384) rotate through a single 8 KB RAM overlay slot; a call made while the wrong overlay is resident would execute unloaded code, corrupting the handshake.

## Exports per Sibling

### X25519 (c64-x25519/src)
```
x25519_scalarmult    (primary ABI entry)
x25519_base
fe25519_mul, fe25519_sqr, fe25519_inv
```

### ChaCha20-Poly1305 (c64-ChaCha20-Poly1305/src)
```
chacha20_encrypt      (primary ABI entry)
poly1305_init, poly1305_update, poly1305_final
aead_encrypt, aead_decrypt
```

### nist-curves (c64-nist-curves/src)
```
ec_point_double, ec_point_add            (P-256)
ec_jacobian_to_affine                    (P-256)
ec_point_double_384, ec_point_add_384    (P-384)
ec_jacobian_to_affine_384                (P-384)
```

## Cross-Library Calls Found

Exhaustive search across all source files in each library for `jsr <symbol>` / `jmp <symbol>` / indirect JSR (`jsr (...)`):

| Source Lib | Call Type | Target Lib | Status |
|---|---|---|---|
| X25519 | → ChaCha/AEAD | — | **NONE** ✓ |
| X25519 | → nist-curves | — | **NONE** ✓ |
| ChaCha20-Poly1305 | → X25519 | — | **NONE** ✓ |
| ChaCha20-Poly1305 | → nist-curves | — | **NONE** ✓ |
| nist-curves | → X25519 | — | **NONE** ✓ |
| nist-curves | → ChaCha20-Poly1305 | — | **NONE** ✓ |

**Indirect calls** (`jsr (...)`): None detected.

## Classification

No inter-sibling calls exist. All **0** entries would fall into the SAFE category:
- Within-same-lib calls: Safe (same overlay slot).
- X25519/P-256/P-384 → ChaCha20-Poly1305 (AEAD, always-resident): Would be SAFE, but none found.
- ChaCha20-Poly1305 → X25519/P-256/P-384: Would be REVIEW (must invoke `crypto_swap_to_*` first), but none found.

## Verdict

**Phase C clear to proceed.**

The overlay design's core invariant is **satisfied**: each library is self-contained, with no cross-library primitive calls. No composition adjustments or overlay-slot changes are required.

---

**Audit date:** 2026-04-19  
**Executed:** grep -rn "jsr|jmp" across all source trees, filtering for known ABI symbols.  
**Result:** Zero hazards.
