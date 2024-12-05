#ifndef	__R12A_RX_DESC_H__
#define	__R12A_RX_DESC_H__

#define R12A_RXDW1_AMSDU        0x00002000
#define R12A_RXDW1_AMPDU        0x00008000
#define R12A_RXDW1_CKSUM_ERR    0x00100000
#define R12A_RXDW1_IPV6         0x00200000
#define R12A_RXDW1_UDP          0x00400000
#define R12A_RXDW1_CKSUM        0x00800000

#define R12A_RXDW2_RPT_C2H      0x10000000

#define R12A_RXDW3_RATE_M       0x0000007f
#define R12A_RXDW3_RATE_S       0

#define R12A_RXDW4_SPLCP        0x00000001
#define R12A_RXDW4_LDPC         0x00000002
#define R12A_RXDW4_STBC         0x00000004
#define R12A_RXDW4_BW_M         0x00000030
#define R12A_RXDW4_BW_S         4
#define R12A_RXDW4_BW20         0
#define R12A_RXDW4_BW40         1
#define R12A_RXDW4_BW80         2
#define R12A_RXDW4_BW160        3

#endif
