; src/crypto_abi.inc — public crypto API consumed by TLS/HTTP layers.
;
; Drop-in contract: any implementation (in-tree today, vendored sibling
; library tomorrow) must export these exact symbols with these exact
; calling conventions. Swapping implementation = changing the link line,
; no call-site changes.
;
; Sibling library correspondence (from Phase 0 discovery):
;   x25519/fe25519 symbols        → c64-x25519
;   chacha20/poly1305/aead symbols → c64-ChaCha20-Poly1305
;   ec_point_* symbols             → c64-nist-curves (P-256; P-384 deferred)
;   sha256 symbols                 → in-tree only, no sibling equivalent

.import x25519_scalarmult
.import fe25519_mul, fe25519_sqr, fe25519_inv

.import chacha20_encrypt
.import poly1305_init, poly1305_update, poly1305_final
.import aead_encrypt, aead_decrypt

.import sha256_init, sha256_update, sha256_final

.import ec_point_double, ec_point_add, ec_jacobian_to_affine

; P-384 symbols NOT imported — stubbed per project_p384_stubbed.
; Future: ec_point_double_384, ec_point_add_384, ec_jacobian_to_affine_384
