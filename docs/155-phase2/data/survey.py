#!/usr/bin/env python3
"""S3 chain survey: fetch each host's chain with the C64 client's exact offer."""
import hashlib, json, re, subprocess, sys, datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

HOSTS = sys.argv[1:]
C64_OFFER = ["-tls1_3", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256",
             "-groups", "X25519", "-sigalgs", "ECDSA+SHA256"]

def keydesc(k):
    if isinstance(k, ec.EllipticCurvePublicKey): return "EC-" + k.curve.name
    if isinstance(k, rsa.RSAPublicKey): return f"RSA-{k.key_size}"
    return type(k).__name__

def spki(c):
    return hashlib.sha256(c.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

def fetch(host, offer):
    cmd = ["openssl", "s_client", "-connect", f"{host}:443", "-servername", host,
           "-showcerts", "-verify_return_error"] + offer
    p = subprocess.run(cmd, input=b"", capture_output=True, timeout=25)
    out = p.stdout.decode(errors="replace")
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", out, re.S)
    ver = re.search(r"Verify return code: (\d+) \(([^)]*)\)", out)
    sig = re.search(r"Peer signature type: (\S+)", out)
    cph = re.search(r"New, TLSv1.3, Cipher is (\S+)", out)
    fetch.last = {"peer_sig": sig.group(1) if sig else None, "cipher": cph.group(1) if cph else None, "rc": p.returncode}
    return [x509.load_pem_x509_certificate(p.encode()) for p in pems], (ver.group(0) if ver else p.stderr.decode()[-200:].strip())

rows = []
for h in HOSTS:
    r = {"host": h}
    try:
        certs, ver = fetch(h, C64_OFFER)
        r["verify"] = ver
        r.update(fetch.last)
        if not certs:
            r["c64_reachable"] = False
            certs, ver = fetch(h, ["-tls1_3"]) or ([], "")
            r["verify_default"] = ver
        else:
            r["c64_reachable"] = True
        if certs:
            leaf = certs[0]
            r["leaf_key"] = keydesc(leaf.public_key())
            r["c64_reachable"] = (r["c64_reachable"] and r["leaf_key"] == "EC-secp256r1"
                                  and fetch.last.get("peer_sig") == "ecdsa_secp256r1_sha256" and fetch.last["rc"] == 0)
            r["leaf_sigalg"] = leaf.signature_algorithm_oid._name
            r["leaf_der_len"] = len(leaf.public_bytes(serialization.Encoding.DER))
            r["leaf_tbs_len"] = len(leaf.tbs_certificate_bytes)
            r["leaf_spki"] = spki(leaf)
            r["leaf_not_after"] = leaf.not_valid_after_utc.date().isoformat()
            r["leaf_days"] = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days
            r["issuer"] = leaf.issuer.rfc4514_string()
            r["chain_len"] = len(certs)
            if len(certs) > 1:
                i = certs[1]
                r["int_subject"] = i.subject.rfc4514_string()
                r["int_key"] = keydesc(i.public_key())
                r["int_sigalg"] = i.signature_algorithm_oid._name
                r["int_spki"] = spki(i)
                r["int_not_after"] = i.not_valid_after_utc.date().isoformat()
                # confirm leaf is really signed by certs[1]
                try:
                    leaf.verify_directly_issued_by(i); r["leaf_by_int"] = True
                except Exception as e:
                    r["leaf_by_int"] = f"NO: {e}"
    except Exception as e:
        r["error"] = repr(e)[:200]
    rows.append(r)
    print(json.dumps(r), flush=True)
