; src/net_abi.inc — public networking API consumed by TLS/HTTP layers.
;
; Drop-in contract: any backend (ip65/RR-Net today, UCI/U64E next) must
; export these exact symbols. Swapping backend = link-time choice via
; different ld65 cfg + different net/<backend>/*.o files. No changes
; to TLS or HTTP sources.

.import net_init
.import net_dhcp_acquire
.import net_poll

.import net_tcp_connect
.import net_tcp_send
.import net_tcp_close
.import net_tcp_set_recv_cb

.import net_dns_resolve

.import net_local_ip
.import net_resolved_ip
.import net_last_error
.import net_tcp_state
