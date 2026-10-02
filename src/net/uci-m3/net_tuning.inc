; src/net/uci-m3/net_tuning.inc — BACKEND=uci-m3 tuning constants.
;
; The M3 variant links no TLS code, so the post-ServerHello drain and
; cert_buf do not exist here. src/exports.s still publishes cert_buf_size,
; so the equate is defined; 0 says "no cert_buf in this image".
NET_SH_DRAIN_OUTER = 1
NET_SH_DRAIN_INNER = 1
CERT_BUF_SIZE = 0
