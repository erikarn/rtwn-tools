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
		printf("  VAL: 0x%02x\n", val);
	} else if (ptr_len == 2) {
		val = le16toh(*(uint16_t *) ptr);
		printf("  VAL: 0x%04x\n", val);
	} else if (ptr_len == 4) {
		val = le16toh(*(uint32_t *) ptr);
		printf("  VAL: 0x%08x\n", val);
	}
}

static void
handle_usb_urb_control_read(usbpcap_t *up, usbpf_urb_t *urb)
{
	/*
	 * Read requests should have two parts, the device request
	 * and the read reply.
	 *
	 * They're split, so for now we only print out the ones
	 * we have.
	 */

	/* XXX methodize */
	if (urb->hdr.up_frames != 2) {
		printf("ERROR: %s: expecting 2 frames, got %d frames\n",
		    __func__,
		    urb->hdr.up_frames);
		goto finish;
	}

	/* XXX methodize */
	if ((urb->payloads->frame_array[0]->flags & USBPF_FRAMEFLAG_READ) != 0) {
		printf("ERROR: %s: expected frame 0 to be WRITE",
		    __func__);
		goto finish;
	}
	/* XXX methodize */
	if ((urb->payloads->frame_array[1]->flags & USBPF_FRAMEFLAG_READ) == 0) {
		printf("ERROR: %s: expected frame 1 to be READ",
		    __func__);
		goto finish;
	}

	/* If we have a buffer for 0, print it */
	if ((urb->payloads->frame_array[0]->buf != NULL)) {
		handle_usb_subframe_usb_device_request(
		    urb->payloads->frame_array[0]->buf,
		    urb->payloads->frame_array[0]->buf_length);
	}

	/* If we have a buffer for 1, print it */
	if ((urb->payloads->frame_array[1]->buf != NULL)) {
		handle_usb_subframe_reg_value(
		    urb->payloads->frame_array[1]->buf,
		    urb->payloads->frame_array[1]->buf_length);
	}


finish:
	usb_urb_free(urb);
}

static void
handle_usb_urb_control_write(usbpcap_t *up, usbpf_urb_t *urb)
{
	/*
	 * Write requests should have two parts, the device request
	 * and value, and then the completion.
	 */

	/* XXX methodize */
	if (urb->hdr.up_frames != 2) {
		printf("ERROR: %s: expecting 2 frames, got %d frames\n",
		    __func__,
		    urb->hdr.up_frames);
		goto finish;
	}

	/* XXX methodize */
	if ((urb->payloads->frame_array[0]->flags & USBPF_FRAMEFLAG_READ) != 0) {
		printf("ERROR: %s: expected frame 0 to be WRITE",
		    __func__);
		goto finish;
	}
	/* XXX methodize */
	if ((urb->payloads->frame_array[1]->flags & USBPF_FRAMEFLAG_READ) != 0) {
		printf("ERROR: %s: expected frame 1 to be WRITE",
		    __func__);
		goto finish;
	}

	/* If we have a buffer for 0, print it */
	if ((urb->payloads->frame_array[0]->buf != NULL)) {
		handle_usb_subframe_usb_device_request(
		    urb->payloads->frame_array[0]->buf,
		    urb->payloads->frame_array[0]->buf_length);
	}

	/* If we have a buffer for 1, print it */
	if ((urb->payloads->frame_array[1]->buf != NULL)) {
		handle_usb_subframe_usb_device_request(
		    urb->payloads->frame_array[1]->buf,
		    urb->payloads->frame_array[1]->buf_length);
	}


finish:
	usb_urb_free(urb);
}



/*
 * Handle the given URB.
 *
 * For now we're only handling EP = 0 (write) and EP = 0x80 (read).
 */
static void
handle_usb_urb(usbpcap_t *up, usbpf_urb_t *urb)
{
	if (urb->hdr.up_endpoint == 0x80) {
		handle_usb_urb_control_read(up, urb);
		return;
	}
	if (urb->hdr.up_endpoint == 0x00) {
		handle_usb_urb_control_write(up, urb);
		return;
	}
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
