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

static void
handle_usb_subframe_usb_device_request(const uint8_t *ptr, int ptr_len)
{
	const usb_device_request_t *dw;

	if (ptr_len < sizeof(usb_device_request_t))
		return;

	dw = (const usb_device_request_t *) ptr;

	printf("  REQ: type=0x%02x, request=0x%02x, value=0x%04x, index=0x%04x, length=0x%04x\n",
	    dw->bmRequestType,
	    dw->bRequest,
	    UGETW(dw->wValue),
	    UGETW(dw->wIndex),
	    UGETW(dw->wLength));
}

static void
handle_usb_subframe_reg_value(const uint8_t *ptr, int ptr_len)
{
	uint32_t val;

	if (ptr_len == 1) {
		val = *(uint8_t *) ptr;
	} else if (ptr_len == 2) {
		val = le16toh(*(uint16_t *) ptr);
	} else if (ptr_len == 4) {
		val = le16toh(*(uint32_t *) ptr);
	} else {
		return;
	}

	printf("  VAL: 0x%08x\n", val);
}

static void
handle_usb_urb(usbpcap_t *up, usbpf_urb_t *urb)
{
#if 0
	if (up->up_endpoint == 0) {		/* Write */
		if (x == 0) {
			/* Request */
			handle_usb_subframe_usb_device_request(ptr, ptr_len);
		} else if (x == 1) {
			/* Payload */
			handle_usb_subframe_reg_value(ptr, ptr_len);
		}
	} else if (up->up_endpoint == 0x80) {	/* Read */
		if (x == 0) {
			/* Request */
			handle_usb_subframe_usb_device_request(ptr, ptr_len);
		} else if (x == 1) {
			/* Payload */
			handle_usb_subframe_reg_value(ptr, ptr_len);
		}
	}
#endif
	usb_urb_free(urb);
}

int
main(int argc, const char *argv[])
{
	usbpcap_t *up;

	up = usbpcap_open(argv[1]);
	if (up == NULL) {
		err(EXIT_FAILURE, "Could not open '%s' for read", argv[1]);
	}

	/* XXX methodize */
	up->iter_cb = handle_usb_urb;

	/* Read packet loop */
	usbpcap_iterate_frames(up);

	usbpcap_close(up); up = NULL;

	exit(0);
}
