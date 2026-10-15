"""Trampoline prologue for rigs that jsr http_get directly (#304).

do_https_get runs trust_pre, which sets tp_mode before the dial. A rig
trampoline skips it, so on a TRUST_STORE=1 build tp_mode stays TP_M_NONE
and cert_pin_check (x509_extract_pubkey's tail call, tls_cert.s) takes
@refuse with C=1: the Certificate step aborts (tls_state=$FF,
tls_last_state=$04). The prologue enters in TP_M_FIRST, which accepts, and
since trust_post is never called nothing is recorded: the real store is
untouched. It bypasses the HTTPS_PIN_SPKI build pin and the TP_M_STORE
compare path; rig_trust_policy.py covers the latter.
"""
from __future__ import annotations

TP_M_FIRST = 2             # src/trust_policy.inc (pinned by test_rig_https_local_trust)


def tp_mode_prologue(labels: dict[str, int]) -> bytes:
    """LDA #TP_M_FIRST / STA tp_mode, or b'' on a build without the store."""
    addr = labels.get("tp_mode")
    if addr is None:
        return b""
    return bytes([0xA9, TP_M_FIRST, 0x8D, addr & 0xFF, (addr >> 8) & 0xFF])
