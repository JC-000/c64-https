# src/net/ip65 — ip65 / RR-Net backend

The current networking backend for c64-https. Implements the `net_*`
ABI declared in `src/net_abi.inc` on top of the ip65 TCP/IP stack with
the RR-Net ethernet driver.

Port of `src/net.asm` from ACME lands here in Phase 3 Batch D. Until
then this directory holds only this README.
