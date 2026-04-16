; src/net/ip65/net_banner.s — ip65 backend banner string
;
; Consumed by boot.s's startup print. Kept as a one-line separate module
; so that the equivalent UCI string in src/net/uci/net.s can live next to
; the rest of the UCI adapter without the ip65 adapter dragging around
; an unrelated .rodata blob.

.export net_banner_str

.segment "RODATA"

net_banner_str:
        .byte "RR-NET (CS8900A) ETHERNET"
        .byte $0d, 0
