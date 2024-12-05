
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
}


/*
 * RTL8188/RTL8192 specific things
 */

static struct usb_chipset_ops chipset_rtl8192_ops = {
	.rx_align = chipset_rtl8192_rx_align,
	.rx_decode = chipset_rtl8192_rx_decode,
};

void
chipset_rtl8192_init(rtwn_app_t *ra)
{
	ra->ops = &chipset_rtl8192_ops;
}
