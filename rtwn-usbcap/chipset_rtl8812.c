
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
#include "r12a_rx_desc.h"

#include "main.h"

static int
chipset_rtl8812_rx_align(rtwn_app_t *ra, int pkt_len, int usb_frame_len)
{
	/* We only need to align to 8 bytes if there's anything left */
	if (pkt_len < usb_frame_len) {
		return roundup2(pkt_len, 8);
	} else {
		return pkt_len;
	}
}

static void
chipset_rtl8812_rx_decode(rtwn_app_t *ra, const uint8_t *buf, int len)
{
	struct rtwn_rx_stat_common rxs = { 0 };
	int pkt_len, info_sz, tot_len;
	int ridx;
	int bw;

	memcpy(&rxs, buf, sizeof(rxs));

	pkt_len = le32toh(rxs.rxdw0) & 0x3fff;
	info_sz = ((le32toh(rxs.rxdw0) >> 16) & 0xf) * 8;
	tot_len = sizeof(rxs) + pkt_len + info_sz;

	printf(" pkt: dw 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x tsf 0x%08x\n",
	    le32toh(rxs.rxdw0),
	    le32toh(rxs.rxdw1),
	    le32toh(rxs.rxdw2),
	    le32toh(rxs.rxdw3),
	    le32toh(rxs.rxdw4),
	    le32toh(rxs.tsf_low));

	printf(" pkt len = %d, info sz = %d, total length = %d\n",
	    pkt_len, info_sz, tot_len);

	printf(" rxdw1: %s%s%s%s%s%s\n",
	    (le32toh(rxs.rxdw1) & R12A_RXDW1_AMSDU) ? " AMSDU" : "",
	    (le32toh(rxs.rxdw1) & R12A_RXDW1_AMPDU) ? " AMPDU" : "",
	    (le32toh(rxs.rxdw1) & R12A_RXDW1_CKSUM_ERR) ? " CKSUM-ERR" : "",
	    (le32toh(rxs.rxdw1) & R12A_RXDW1_IPV6) ? " IPV6" : "",
	    (le32toh(rxs.rxdw1) & R12A_RXDW1_UDP) ? " UDP" : "",
	    (le32toh(rxs.rxdw1) & R12A_RXDW1_CKSUM) ? " CKSUM" : "");

	printf(" rxdw2: %s\n",
	    (le32toh(rxs.rxdw2) & R12A_RXDW2_RPT_C2H) ? " RPT-C2H" : "");

	ridx = le32toh(rxs.rxdw3) & 0x7f;
	printf(" rxdw3: ridx 0x%x\n", ridx);

	bw = (le32toh(rxs.rxdw4) >> 4) & 0x3;
	printf(" rxdw4: %s%s%s BW: %d\n",
	    (le32toh(rxs.rxdw1) & R12A_RXDW4_SPLCP) ? " SPLCP" : "",
	    (le32toh(rxs.rxdw1) & R12A_RXDW4_LDPC) ? " LDPC" : "",
	    (le32toh(rxs.rxdw1) & R12A_RXDW4_STBC) ? " STBC" : "",
	    bw);
}

static void
chipset_rtl8812_tx_decode(rtwn_app_t *ra, const usbpf_urb_t *urb)
{
}

/*
 * RTL8821/RTL8812 specific things
 */

static struct usb_chipset_ops chipset_rtl8812_ops = {
	.rx_align = chipset_rtl8812_rx_align,
	.rx_decode = chipset_rtl8812_rx_decode,
	.tx_decode = chipset_rtl8812_tx_decode,
};

void
chipset_rtl8812_init(rtwn_app_t *ra)
{
	ra->ops = &chipset_rtl8812_ops;
}
