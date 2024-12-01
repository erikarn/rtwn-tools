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

#define	USBPF_URB_COMPLETION_CACHE	32

static usbpf_urb_t *usb_compl[USBPF_URB_COMPLETION_CACHE] = { 0 };

static void
usb_compl_init(void)
{

	memset(&usb_compl, 0, sizeof(usb_compl));
}

static void
usb_compl_flush(void)
{
	int i;

	for (i = 0; i < USBPF_URB_COMPLETION_CACHE; i++) {
		if (usb_compl[i] != NULL) {
			usb_urb_free(usb_compl[i]);
			usb_compl[i] = NULL;
		}
	}
}

/*
 * Lookup, don't remove.
 */
static bool
usb_compl_lookup(int epid)
{
	int i;

	for (i = 0; i < USBPF_URB_COMPLETION_CACHE; i++) {
		if (usb_compl[i] != NULL && usb_compl[i]->hdr.up_endpoint == epid)
			return true;
	}
	return (false);
}

/*
 * Lookup, do remove and return it.
 * Return NULL if it's not found.
 */
static usbpf_urb_t *
usb_compl_fetch(int epid)
{
	int i;

	for (i = 0; i < USBPF_URB_COMPLETION_CACHE; i++) {
		if (usb_compl[i] != NULL && usb_compl[i]->hdr.up_endpoint == epid) {
			usbpf_urb_t *urb = usb_compl[i];
			usb_compl[i] = NULL;
			return (urb);
		}
	}
	return (NULL);
}

/*
 * Add an entry to the completion cache.
 *
 * The completion cache assumes a single pending transfer
 * per endpoint, so if an existing transfer with the same
 * endpoint exists, this routine returns false.
 *
 * It also returns false if there's no space.
 */
static bool
usb_compl_add(usbpf_urb_t *urb)
{
	int i;

	if (usb_compl_lookup(urb->hdr.up_endpoint) == true)
		return (false);

	for (i = 0; i < USBPF_URB_COMPLETION_CACHE; i++) {
		if (usb_compl[i] == NULL) {
			usb_compl[i] = urb;
			return (true);
		}
	}
	return (false);
}

static void
handle_usb_subframe_usb_device_request(const char *label, const uint8_t *ptr, int ptr_len)
{
	const usb_device_request_t *dw;

	if (ptr_len != sizeof(usb_device_request_t)) {
		printf("  INVALID REQ (length %d)\n", ptr_len);
		return;
	}

	dw = (const usb_device_request_t *) ptr;

	/* R29C_REQ_REGS - 0x5 */

	if (dw->bRequest == 0x5) {
		printf("  %s: register=0x%08x, length=%d\n", label,
		    UGETW(dw->wValue), UGETW(dw->wLength));
		return;
	}

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
	} else {
		printf("  INVALID LENGTH (%d bytes)\n", ptr_len);
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
		    "REG READ",
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
		    "REG WRITE",
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



/*
 * Handle the given URB.
 *
 * For now we're only handling EP = 0 (write) and EP = 0x80 (read).
 */
static void
handle_usb_urb(usbpcap_t *up, usbpf_urb_t *urb)
{
//	usbpcap_print_urbpf_header(urb);

	if (urb->hdr.up_type == USBPF_XFERTAP_SUBMIT) {
		usbpf_urb_t *stale_urb;

		/*
		 * If it's a SUBMIT, then push it into the
		 * cache for later.
		 */
		stale_urb = usb_compl_fetch(urb->hdr.up_endpoint);
		if (stale_urb != NULL) {
			/* XXX TODO: at least print it */
			usb_urb_free(stale_urb);
		}

		/* XXX TODO: handle printing the submission if requested */

		/* If we fail to add it, then just free and continue */
		if (usb_compl_add(urb) == false) {
			/* XXX TODO: at least print it */
			usb_urb_free(urb);
		}
		return;
	} else {
		usbpf_urb_t *sub_urb = NULL;

		/*
		 * If it's not a SUBMIT, it's a done (error or otherwise)
		 * so lookup the matching submit urb.
		 */

		sub_urb = usb_compl_fetch(urb->hdr.up_endpoint);

		/* XXX TODO: handle the submission and completion together now */

		if (sub_urb != NULL)
			usb_urb_free(sub_urb);
		usb_urb_free(urb);
	}


#if 0
	if (urb->hdr.up_endpoint == 0x80) {
		handle_usb_urb_control_read(up, urb);
		return;
	}
	if (urb->hdr.up_endpoint == 0x00) {
		handle_usb_urb_control_write(up, urb);
		return;
	}

	printf("UNKNOWN EP: 0x%08x\n", urb->hdr.up_endpoint);

	usb_urb_free(urb);
#endif
}

int
main(int argc, const char *argv[])
{
	usbpcap_t *up;

	usb_compl_init();

	up = usbpcap_open(argv[1]);
	if (up == NULL) {
		err(EXIT_FAILURE, "Could not open '%s' for read", argv[1]);
	}

	/* XXX methodize */
	up->iter_cb = handle_usb_urb;

	/* Read packet loop */
	usbpcap_iterate_frames(up);

	usbpcap_close(up); up = NULL;
	usb_compl_flush();

	exit(0);
}
