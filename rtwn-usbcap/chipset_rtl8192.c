
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

/*
 * RTL8188/RTL8192 specific things
 */

static struct usb_chipset_ops chipset_rtl8192_ops = {
	.rx_align = chipset_rtl8192_rx_align,
};

void
chipset_rtl8192_init(rtwn_app_t *ra)
{
	ra->ops = &chipset_rtl8192_ops;
}
