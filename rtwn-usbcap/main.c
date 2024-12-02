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
#include "usb_compl.h"

#include "main.h"

/*
 * TODO: handle fragmented RX packets!
 *
 * rxdw0 -> rxdw4, tsf_low
 */
static void
handle_usb_bulk_rx_frame(rtwn_app_t *ra, const usbpf_urb_t *urb)
{
	const uint8_t *ptr, *buf;
	int buf_len, ptr_len = 0;

	if (urb->hdr.up_frames != 1 || urb->payloads->num_frames != 1) {
		printf("{ ERROR: %s: expecting 1 frames, got %d frames, %d bufs }",
		    __func__,
		    urb->hdr.up_frames,
		    urb->payloads->num_frames);
		goto finish;
	}

	buf = urb->payloads->frame_array[0]->buf;
	buf_len = urb->payloads->frame_array[0]->buf_length;
	ptr = buf;
	ptr_len = buf_len;

	printf("pkt: start; %d bytes in frame\n", buf_len);

	while (ptr_len > 0) {
		struct rtwn_rx_stat_common rxs = { 0 };
		int pkt_len;
		int info_sz;
		int tot_len;

		if (ptr_len < sizeof(rxs)) {
			printf(" pkt: short (%d bytes)\n", ptr_len);
			break;
		}

		/* Decode rx status */
		memcpy(&rxs, ptr, sizeof(rxs));

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

		printf(" pkt len = %d, info sz = %d\n", pkt_len, info_sz);

		/*
		 * TODO: also need to handle packet fragmentation;
		 * ie if a RX frame straddles >1 RX frame.
		 */
		/* Note: reusing tot_len */
		tot_len = ra->ops->rx_align(ra, tot_len, ptr_len);
		ptr += tot_len;
		ptr_len -= tot_len;
	}

finish:
	printf("pkt: finish; %d bytes unhandled\n", ptr_len);
	return;

}

static void
handle_usb_subframe_usb_device_request(const char *label, const uint8_t *ptr, int ptr_len)
{
	const usb_device_request_t *dw;

	if (ptr_len != sizeof(usb_device_request_t)) {
		printf(" INVALID REQ (length %d)", ptr_len);
		return;
	}

	dw = (const usb_device_request_t *) ptr;

	/* R29C_REQ_REGS - 0x5 */

	if (dw->bRequest == 0x5) {
		printf("%s: 0x%04x (%d) = ", label,
		    UGETW(dw->wValue), UGETW(dw->wLength));
		return;
	}

	printf(" { REQ: type=0x%02x, request=0x%02x, value=0x%04x, index=0x%04x, length=0x%04x }",
	    dw->bmRequestType,
	    dw->bRequest,
	    UGETW(dw->wValue),
	    UGETW(dw->wIndex),
	    UGETW(dw->wLength));
}

void
handle_usb_subframe_reg_value(const uint8_t *ptr, int ptr_len)
{
	uint32_t val;

	if (ptr_len == 1) {
		val = *(uint8_t *) ptr;
		printf("0x%02x", val);
	} else if (ptr_len == 2) {
		val = le16toh(*(uint16_t *) ptr);
		printf("0x%04x", val);
	} else if (ptr_len == 4) {
		val = le32toh(*(uint32_t *) ptr);
		printf("0x%08x", val);
	} else {
		printf("{ INVALID LENGTH (%d bytes) }", ptr_len);
	}
}

static void
handle_usb_urb_control_read(rtwn_app_t *ra, usbpf_urb_t *sub_urb,
    usbpf_urb_t *compl_urb)
{
	/*
	 * Read requests should have two parts, the device request
	 * and the read reply.
	 *
	 * They're split, so for now we only print out the ones
	 * we have.
	 */

	/* XXX methodize */
	if (sub_urb->hdr.up_frames != 2) {
		printf("{ ERROR: %s: expecting 2 frames, got %d frames }",
		    __func__,
		    sub_urb->hdr.up_frames);
		goto finish;
	}
	if (compl_urb->hdr.up_frames != 2) {
		printf("{ ERROR: %s: expecting 2 frames, got %d frames }",
		    __func__,
		    compl_urb->hdr.up_frames);
		goto finish;
	}


	/* XXX methodize */
	if ((sub_urb->payloads->frame_array[0]->flags & USBPF_FRAMEFLAG_READ) != 0) {
		printf("{ expected frame 0 to be WRITE }");
		goto finish;
	}
	/* XXX methodize */
	if ((compl_urb->payloads->frame_array[1]->flags & USBPF_FRAMEFLAG_READ) == 0) {
		printf("{ expected frame 1 to be READ }");
		goto finish;
	}

	/* If we have a buffer for 0, print it */
	if ((sub_urb->payloads->frame_array[0]->buf != NULL)) {
		handle_usb_subframe_usb_device_request(
		    "REG READ",
		    sub_urb->payloads->frame_array[0]->buf,
		    sub_urb->payloads->frame_array[0]->buf_length);
	}

	/* If we have a buffer for 1, print it */
	/*
	 * TODO: buf_length here isn't enough to print the
	 * "right" value length, as it's always 4 bytes.
	 * We'd need instead to use the device_request wLength
	 * parameter here.
	 */
	if ((compl_urb->payloads->frame_array[1]->buf != NULL)) {
		handle_usb_subframe_reg_value(
		    compl_urb->payloads->frame_array[1]->buf,
		    compl_urb->payloads->frame_array[1]->buf_length);
	}


finish:
	return;
}

/*
 * Called to print the result of a control write, sub_urb and
 * compl_urb both exist.
 */
static void
handle_usb_urb_control_write(rtwn_app_t *ra, usbpf_urb_t *sub_urb,
    usbpf_urb_t *compl_urb)
{
	/*
	 * Write requests should have two parts, the device request
	 * and value, and then the completion.
	 */

	/* XXX methodize */
	if (sub_urb->hdr.up_frames != 2) {
		printf("ERROR: %s: expecting 2 frames, got %d frames\n",
		    __func__,
		    sub_urb->hdr.up_frames);
		goto finish;
	}

	/* XXX methodize */
	if ((sub_urb->payloads->frame_array[0]->flags & USBPF_FRAMEFLAG_READ) != 0) {
		printf("ERROR: %s: expected frame 0 to be WRITE\n",
		    __func__);
		goto finish;
	}
	/* XXX methodize */
	if ((sub_urb->payloads->frame_array[1]->flags & USBPF_FRAMEFLAG_READ) != 0) {
		printf("ERROR: %s: expected frame 1 to be WRITE\n",
		    __func__);
		goto finish;
	}

	/* If we have a buffer for 0, print it */
	if ((sub_urb->payloads->frame_array[0]->buf != NULL)) {
		handle_usb_subframe_usb_device_request(
		    "REG WRITE",
		    sub_urb->payloads->frame_array[0]->buf,
		    sub_urb->payloads->frame_array[0]->buf_length);
	}

	/* If we have a buffer for 1, print it */
	if ((sub_urb->payloads->frame_array[1]->buf != NULL)) {
		handle_usb_subframe_reg_value(
		    sub_urb->payloads->frame_array[1]->buf,
		    sub_urb->payloads->frame_array[1]->buf_length);
	}

finish:
	return;
}
static void
handle_usb_urb_compl_print_status(usbpf_urb_t *urb)
{
	if (urb->hdr.up_type == USBPF_XFERTAP_DONE &&
	    urb->hdr.up_error != USB_ERR_NORMAL_COMPLETION) {
		printf(" (%d) (%s)", urb->hdr.up_type,
		    usb_errstr(urb->hdr.up_error));
	}
}


/*
 * print/etc the stale URB
 *
 * The caller will free it afterwards.
 */
static void
handle_urb_stale_complete(rtwn_app_t *ra, usbpf_urb_t *urb)
{
	/* TODO */
}

/*
 * print/etc the submitted URB.
 *
 * if is_error is true then the URB couldn't be added
 * into the completion cache, so we should print what we have.
 *
 * The caller will free it afterwards.
 */
static void
handle_urb_submission(rtwn_app_t *ra, usbpf_urb_t *urb, bool is_error)
{
	/* EP 0x80 = control read */
	/* EP 0x00 = control write */

	/* EP 0x84 = bulk read (rx data) */

	/* EP 0x08 = bulk write (tx data) */
	/* TODO: more bulk EP */
}

/*
 * print/etc the submitted + completed URB.
 *
 * The caller will free them afterwards.
 *
 * Note: compl_urb will always be set, but sub_urb may not be!
 */
static void
handle_urb_completion(rtwn_app_t *ra, usbpf_urb_t *sub_urb,
    usbpf_urb_t *compl_urb)
{
	struct timeval tv_sub = { 0 }, tv_comp = { 0 };
	struct tm *tm;
	size_t len;
	int ep;
	char buf[64];

	ep = compl_urb->hdr.up_endpoint;
	if (sub_urb != NULL)
		tv_sub = sub_urb->tv;
	tv_comp = compl_urb->tv;

	(void) tv_sub;

	tm = localtime(&tv_comp.tv_sec);
	len = strftime(buf, sizeof(buf), "%H:%M:%S", tm);

	if (sub_urb == NULL) {
		printf("%.*s%06ld: COMP: EP: 0x%.02x: no matching SUBMIT\n",
		    (int) len,
		    buf,
		    tv_comp.tv_usec,
		    ep);
	}

	/* EP 0x80 = control read */
	/* EP 0x00 = control write */

	switch (ep) {
	case 0x81:
	case 0x82:
	case 0x83:
	case 0x84:
	case 0x85:
		/* bulk RX read */
		handle_usb_bulk_rx_frame(ra, compl_urb);
		printf("\n");
		break;
	case 0x80:
		/* control read */
		printf("%.*s%06ld: ",
		    (int) len,
		    buf,
		    tv_comp.tv_usec);
		handle_usb_urb_control_read(ra, sub_urb, compl_urb);
		handle_usb_urb_compl_print_status(compl_urb);
		printf("\n");
		break;
	case 0x00:
		/* control write */
		/*
		 * Both register and payload are in the submit urb;
		 * the status is in the completion urb.
		 */
		printf("%.*s%06ld: ",
		    (int) len,
		    buf,
		    tv_comp.tv_usec);
		handle_usb_urb_control_write(ra, sub_urb, compl_urb);
		handle_usb_urb_compl_print_status(compl_urb);
		printf("\n");
		break;
	default:
		printf("%.*s%06ld: COMP: EP 0x%.02x: unknown EP\n",
		    (int) len,
		    buf,
		    tv_comp.tv_usec,
		    ep);
		break;
	}
}

/*
 * Handle the given URB.
 *
 * For now we're only handling EP = 0 (write) and EP = 0x80 (read).
 */
static void
handle_usb_urb(usbpcap_t *up, void *cbdata, usbpf_urb_t *urb)
{
	rtwn_app_t *ra = (rtwn_app_t *) cbdata;

//	usbpcap_print_urbpf_header(urb);

	if (urb->hdr.up_type == USBPF_XFERTAP_SUBMIT) {
		usbpf_urb_t *stale_urb;

		/*
		 * If it's a SUBMIT, then push it into the
		 * cache for later.
		 */
		stale_urb = usb_compl_fetch(urb->hdr.up_endpoint);
		if (stale_urb != NULL) {
			handle_urb_stale_complete(ra, stale_urb);
			usb_urb_free(stale_urb);
		}


		/* If we fail to add it, then just free and continue */
		if (usb_compl_add(urb) == false) {
			handle_urb_submission(ra, urb, true);
			usb_urb_free(urb);
		}
		handle_urb_submission(ra, urb, false);
		return;
	} else {
		usbpf_urb_t *sub_urb = NULL;

		/*
		 * If it's not a SUBMIT, it's a done (error or otherwise)
		 * so lookup the matching submit urb.
		 */
		sub_urb = usb_compl_fetch(urb->hdr.up_endpoint);
		handle_urb_completion(ra, sub_urb, urb);

		if (sub_urb != NULL)
			usb_urb_free(sub_urb);
		usb_urb_free(urb);
	}
}

int
main(int argc, const char *argv[])
{
	rtwn_app_t ra = { 0 };

	usb_compl_init();

	ra.up = usbpcap_open(argv[1]);
	if (ra.up == NULL) {
		err(EXIT_FAILURE, "Could not open '%s' for read", argv[1]);
	}

	/* XXX methodize */
	ra.up->iter_cb = handle_usb_urb;
	ra.up->iter_cbdata = &ra;

	chipset_rtl8812_init(&ra);

	/* Read packet loop */
	usbpcap_iterate_frames(ra.up);

	usbpcap_close(ra.up); ra.up = NULL;
	usb_compl_flush();

	exit(0);
}
