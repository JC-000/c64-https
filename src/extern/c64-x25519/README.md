# c64-x25519 (vendored)

Placeholder for vendored sources from the sibling `c64-x25519` project.

Vendoring happens in a follow-up PR after the base ACME→ca65 refactor is
merged. See `src/crypto_abi.inc` for the public symbols this library is
expected to provide. ABI alignment was verified in Phase 0 discovery.

Baseline profile: no-REU. Profile A (REU mul tables) is a future opt-in.
