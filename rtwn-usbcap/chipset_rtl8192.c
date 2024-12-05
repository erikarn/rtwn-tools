
#include <sys/param.h>
#include <sys/endian.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/queue.h>
#include <net/if.h>
#include <net/bpf.h>
#include <dev/usb/usb.h>
#include <dev/usb/usb.h>
#include <dev/usb/usb_pf.h>
#include <dev/usb/usbdi.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sysexits.h>
#include <err.h>

#include "libusbpcap.h"

#include "if_rtwn_desc.h"
#include "r92_rx_desc.h"
#include "r92_tx_desc.h"

#include "main.h"

static int
chipset_rtl8192_rx_align(rtwn_app_t *ra, int pkt_len, int usb_frame_len)
{

	return roundup2(pkt_len, 128);
}

static void
chipset_rtl8192_rx_decode(rtwn_app_t *ra, const uint8_t *buf, int len)
{
	struct rtwn_rx_stat_common rxs = { 0 };
	int pkt_len, info_sz, tot_len;

	memcpy(&rxs, buf, sizeof(rxs));

	pkt_len = le32toh(rxs.rxdw0) & 0x3fff;
	info_sz = ((le32toh(rxs.rxdw0) >> 16) & 0xf) * 8;
	tot_len = sizeof(rxs) + pkt_len + info_sz;

	printf(" RX: dw 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x tsf 0x%08x\n",
	    le32toh(rxs.rxdw0),
	    le32toh(rxs.rxdw1),
	    le32toh(rxs.rxdw2),
	    le32toh(rxs.rxdw3),
	    le32toh(rxs.rxdw4),
	    le32toh(rxs.tsf_low));
	printf(" RX: pkt len = %d, info sz = %d, total length = %d\n",
	    pkt_len, info_sz, tot_len);

	printf(" RX: rxdw0: %s%s%s%s%s%s%s%s%s cipher %d shift %d\n",
	    le32toh(rxs.rxdw0) & R92C_RXDW0_CRCERR ? " CRCERR" : "",
	    le32toh(rxs.rxdw0) & R92C_RXDW0_ICVERR ? " ICVERR" : "",
	    le32toh(rxs.rxdw0) & R92C_RXDW0_QOS ? " QOS" : "",
	    le32toh(rxs.rxdw0) & R92C_RXDW0_PHYST ? " PHYST" : "",
	    le32toh(rxs.rxdw0) & R92C_RXDW0_SWDEC ? " SWDEC" : "",
	    le32toh(rxs.rxdw0) & R92C_RXDW0_LS ? " LS" : "",
	    le32toh(rxs.rxdw0) & R92C_RXDW0_FS ? " FS" : "",
	    le32toh(rxs.rxdw0) & R92C_RXDW0_EOR ? " EOR" : "",
	    le32toh(rxs.rxdw0) & R92C_RXDW0_OWN ? " OWN" : "",
	    (le32toh(rxs.rxdw0) >> 20) & 0x7,
	    (le32toh(rxs.rxdw0) >> 24) & 0x3);

	printf(" RX: rxdw1: %s%s%s%s%s macid %d\n",
	    le32toh(rxs.rxdw1) & R92C_RXDW1_AMSDU ? " AMSDU" : "",
	    le32toh(rxs.rxdw1) & R92C_RXDW1_AMPDU_MORE ? " AMPDU_MORE" : "",
	    le32toh(rxs.rxdw1) & R92C_RXDW1_AMPDU ? " AMPDU" : "",
	    le32toh(rxs.rxdw1) & R92C_RXDW1_MC ? " MC" : "",
	    le32toh(rxs.rxdw1) & R92C_RXDW1_BC ? " BC" : "",
	    le32toh(rxs.rxdw1) & 0x1f);

	printf(" RX: rxdw3: %s%s%s%s rate 0x%x bssid_fit %d\n",
	    le32toh(rxs.rxdw3) & R92C_RXDW3_HT ? " HT" : "",
	    le32toh(rxs.rxdw3) & R92C_RXDW3_SPLCP ? " SPLCP" : "",
	    le32toh(rxs.rxdw3) & R92C_RXDW3_HT40 ? " HT40" : "",
	    le32toh(rxs.rxdw3) & R92C_RXDW3_HTC ? " HTC" : "",
	    le32toh(rxs.rxdw3) & 0x3f,
	    (le32toh(rxs.rxdw3) >> 12) & 0x3);
}

static void
chipset_rtl8192_tx_decode(rtwn_app_t *ra, const usbpf_urb_t *urb)
{
	struct r92c_tx_desc txs;
	const uint8_t *buf;
	int len;

	/* XXX for now, assume a single buffer in the URB */
	buf = urb->payloads->frame_array[0]->buf;
	len = urb->payloads->frame_array[0]->buf_length;

	if (len < sizeof(txs))
		return;

	memcpy(&txs, buf, sizeof(txs));

	printf("TX: pktlen=%d offset=%d %s%s%s%s\n",
	    le16toh(txs.pktlen),
	    txs.offset,
	    (txs.offset & R92C_FLAGS0_BMCAST) ? " BMCAST" : "",
	    (txs.offset & R92C_FLAGS0_LSG) ? " LSG" : "",
	    (txs.offset & R92C_FLAGS0_FSG) ? " FSG" : "",
	    (txs.offset & R92C_FLAGS0_OWN) ? " OWN" : "");

	printf(" TX: txdw1 (0x%08x): macid %d qsel %d raid %d cipher %d pktoff %d %s%s\n",
	    le32toh(txs.txdw1),
	    le32toh(txs.txdw1) & 0x1f,
	    (le32toh(txs.txdw1) >> 8) & 0x1f,
	    (le32toh(txs.txdw1) >> 16) & 0xf,
	    (le32toh(txs.txdw1) >> 22) & 0x3,
	    (le32toh(txs.txdw1) >> 26) & 0x1f,
	    le32toh(txs.txdw1) & R92C_TXDW1_AGGEN ? " AGGEN" :  "",
	    le32toh(txs.txdw1) & R92C_TXDW1_AGGBK ? " AGGBK" :  "");

	printf(" TX: txdw2: (0x%08x): ampdu_den %d %s\n",
	    le32toh(txs.txdw2),
	    (le32toh(txs.txdw2) >> 20) & 0x7,
	    le32toh(txs.txdw2) & R92C_TXDW2_CCX_RPT ? " CCX_RPT" : "");

	printf(" TX: txdw3: (0x%04x)\n", le16toh(txs.txdw3));
	printf(" TX: txdseq: %d\n", le16toh(txs.txdseq));

	printf(" TX: txdw4: (0x%08x): rtsrate 0x%d seq_sel %d port_id %d data_sco %d rts_sco %d\n",
	    le32toh(txs.txdw4),
	    le32toh(txs.txdw4) & 0x1f,
	    (le32toh(txs.txdw4) >> 6) & 0x3,
	    (le32toh(txs.txdw4) >> 14) & 0xff, /* XXX need to figure out this field def */
	    (le32toh(txs.txdw4) >> 20) & 0x3,
	    (le32toh(txs.txdw4) >> 28) & 0x3,
	    le32toh(txs.txdw4) & R92C_TXDW4_HWSEQ_EN ? " HWSEQ" :  "",
	    le32toh(txs.txdw4) & R92C_TXDW4_DRVRATE ? " DRVRATE" :  "",
	    le32toh(txs.txdw4) & R92C_TXDW4_CTS2SELF ? " CTS2SELF" :  "",
	    le32toh(txs.txdw4) & R92C_TXDW4_RTSEN ? " RTSEN" :  "",
	    le32toh(txs.txdw4) & R92C_TXDW4_HWRTSEN ? " HWRTSEN" :  "",
	    le32toh(txs.txdw4) & R92C_TXDW4_SCO_SCA ? " SCO_A" :  "",
	    le32toh(txs.txdw4) & R92C_TXDW4_SCO_SCB ? " SCO_B" :  "",
	    le32toh(txs.txdw4) & R92C_TXDW4_DATA_SHPRE ? " DATA_SHPRE" :  "",
	    le32toh(txs.txdw4) & R92C_TXDW4_DATA_BW40 ? " DATA_BW40" :  "",
	    le32toh(txs.txdw4) & R92C_TXDW4_RTS_SHORT ? " RTS_SHORT" :  "",
	    le32toh(txs.txdw4) & R92C_TXDW4_RTS_BW40 ? " RTS_BW40" :  "");

	printf(" TX: txdw5: (0x%08x): datarate 0x%02x data_fb_lmt %d rts_fb_limit %d retry_limit %d aggnm %d %s\n",
	    le32toh(txs.txdw5),
	    le32toh(txs.txdw5) & 0x3f,
	    (le32toh(txs.txdw5) >> 8) & 0x1f,
	    (le32toh(txs.txdw5) >> 13) & 0xf,
	    (le32toh(txs.txdw5) >> 18) & 0x3f,
	    (le32toh(txs.txdw5) >> 24) & 0xff,
	    le32toh(txs.txdw5) & R92C_TXDW5_SGI ? " SGI" :  "");

	printf(" TX: txdw6: (0x%08x): max_agg %d\n",
	    le32toh(txs.txdw6),
	    (le32toh(txs.txdw6) >> 11) & 0x1f);
}


/*
 * RTL8188/RTL8192 specific things
 */

static struct usb_chipset_ops chipset_rtl8192_ops = {
	.rx_align = chipset_rtl8192_rx_align,
	.rx_decode = chipset_rtl8192_rx_decode,
	.tx_decode = chipset_rtl8192_tx_decode,
};

void
chipset_rtl8192_init(rtwn_app_t *ra)
{
	ra->ops = &chipset_rtl8192_ops;
}
