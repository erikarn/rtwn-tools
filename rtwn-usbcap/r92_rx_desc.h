#ifndef	__R92_RX_DESC_H__
#define	__R92_RX_DESC_H__

/* rxdw0 */
#define R92C_RXDW0_PKTLEN_M     0x00003fff
#define R92C_RXDW0_PKTLEN_S     0
#define R92C_RXDW0_CRCERR       0x00004000
#define R92C_RXDW0_ICVERR       0x00008000
#define R92C_RXDW0_INFOSZ_M     0x000f0000
#define R92C_RXDW0_INFOSZ_S     16
#define R92C_RXDW0_CIPHER_M     0x00700000
#define R92C_RXDW0_CIPHER_S     20
#define R92C_RXDW0_QOS          0x00800000
#define R92C_RXDW0_SHIFT_M      0x03000000
#define R92C_RXDW0_SHIFT_S      24
#define R92C_RXDW0_PHYST        0x04000000
#define R92C_RXDW0_SWDEC        0x08000000
#define R92C_RXDW0_LS           0x10000000
#define R92C_RXDW0_FS           0x20000000
#define R92C_RXDW0_EOR          0x40000000
#define R92C_RXDW0_OWN          0x80000000

/* rxdw1 */
#define R92C_RXDW1_MACID_M      0x0000001f
#define R92C_RXDW1_MACID_S      0
#define R92C_RXDW1_AMSDU        0x00002000
#define R92C_RXDW1_AMPDU_MORE   0x00004000
#define R92C_RXDW1_AMPDU        0x00008000
#define R92C_RXDW1_MC           0x40000000
#define R92C_RXDW1_BC           0x80000000

/* rxdw2 */

/* rxdw3 */
#define R92C_RXDW3_RATE_M       0x0000003f
#define R92C_RXDW3_RATE_S       0
#define R92C_RXDW3_HT           0x00000040
#define R92C_RXDW3_SPLCP        0x00000100
#define R92C_RXDW3_HT40         0x00000200
#define R92C_RXDW3_HTC          0x00000400
#define R92C_RXDW3_BSSID_FIT_M  0x00003000
#define R92C_RXDW3_BSSID_FIT_S  12

/* rxdw4 */


#endif	/* __R92_RX_DESC_H__ */
