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

static const char *xfertype_table[USB_XFERTYPE_MAX] = {
	[UE_CONTROL]		    = "CTRL",
	[UE_ISOCHRONOUS]		= "ISOC",
	[UE_BULK]		       = "BULK",
	[UE_INTERRUPT]		  = "INTR"
};

static const char *speed_table[USB_SPEED_MAX] = {
	[USB_SPEED_FULL] = "FULL",
	[USB_SPEED_HIGH] = "HIGH",
	[USB_SPEED_LOW] = "LOW",
	[USB_SPEED_VARIABLE] = "VARI",
	[USB_SPEED_SUPER] = "SUPER",
};

static const char *errstr_table[USB_ERR_MAX] = {
	[USB_ERR_NORMAL_COMPLETION]     = "0",
	[USB_ERR_PENDING_REQUESTS]      = "PENDING_REQUESTS",
	[USB_ERR_NOT_STARTED]	   = "NOT_STARTED",
	[USB_ERR_INVAL]		 = "INVAL",
	[USB_ERR_NOMEM]		 = "NOMEM",
	[USB_ERR_CANCELLED]	     = "CANCELLED",
	[USB_ERR_BAD_ADDRESS]	   = "BAD_ADDRESS",
	[USB_ERR_BAD_BUFSIZE]	   = "BAD_BUFSIZE",
	[USB_ERR_BAD_FLAG]	      = "BAD_FLAG",
	[USB_ERR_NO_CALLBACK]	   = "NO_CALLBACK",
	[USB_ERR_IN_USE]		= "IN_USE",
	[USB_ERR_NO_ADDR]	       = "NO_ADDR",
	[USB_ERR_NO_PIPE]	       = "NO_PIPE",
	[USB_ERR_ZERO_NFRAMES]	  = "ZERO_NFRAMES",
	[USB_ERR_ZERO_MAXP]	     = "ZERO_MAXP",
	[USB_ERR_SET_ADDR_FAILED]       = "SET_ADDR_FAILED",
	[USB_ERR_NO_POWER]	      = "NO_POWER",
	[USB_ERR_TOO_DEEP]	      = "TOO_DEEP",
	[USB_ERR_IOERROR]	       = "IOERROR",
	[USB_ERR_NOT_CONFIGURED]	= "NOT_CONFIGURED",
	[USB_ERR_TIMEOUT]	       = "TIMEOUT",
	[USB_ERR_SHORT_XFER]	    = "SHORT_XFER",
	[USB_ERR_STALLED]	       = "STALLED",
	[USB_ERR_INTERRUPTED]	   = "INTERRUPTED",
	[USB_ERR_DMA_LOAD_FAILED]       = "DMA_LOAD_FAILED",
	[USB_ERR_BAD_CONTEXT]	   = "BAD_CONTEXT",
	[USB_ERR_NO_ROOT_HUB]	   = "NO_ROOT_HUB",
	[USB_ERR_NO_INTR_THREAD]	= "NO_INTR_THREAD",
	[USB_ERR_NOT_LOCKED]	    = "NOT_LOCKED",
};


const char *
usb_errstr(uint32_t error)
{
	if (error >= USB_ERR_MAX || errstr_table[error] == NULL)
		return ("UNKNOWN");
	else
		return (errstr_table[error]);
}

const char *
usb_speedstr(uint8_t speed)
{
	if (speed >= USB_SPEED_MAX  || speed_table[speed] == NULL)
		return ("UNKNOWN");
	else
		return (speed_table[speed]);
}

const char *
usb_xferstr(uint8_t type)
{
	if (type >= USB_XFERTYPE_MAX  || xfertype_table[type] == NULL)
		return ("UNKN");
	else
		return (xfertype_table[type]);
}


usbpcap_t *
usbpcap_open(const char *filename)
{
	struct usbcap_filehdr uf;
	usbpcap_t *up = NULL;
	int ret;
	int fd = -1;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		warn("Could not open '%s' for read", filename);
		goto error;
	}

	/* Validate header */
	ret = read(fd, &uf, sizeof(uf));
	if (ret != sizeof(uf)) {
		warn("Short read (%d bytes, expected %zd bytes)",
		    ret, sizeof(uf));
		goto error;
	}
	if (le32toh(uf.magic) != USBCAP_FILEHDR_MAGIC) {
		fprintf(stderr, "Invalid magic header (0x%08x) "
		    "in USB capture file header\n",
		    (unsigned int) le32toh(uf.magic));
		goto error;
	}

	if (le32toh(uf.major) != 0) {
		fprintf(stderr, "Invalid major version (%d)\n",
		    (int) le32toh(uf.major));
		goto error;
	}
	if (le32toh(uf.minor) != 3) {
		fprintf(stderr, "Invalid minor version (%d)\n",
		    (int) le32toh(uf.minor));
		goto error;
	}

	up = calloc(1, sizeof(*up));
	if (up == NULL) {
		warn("Unable to allocate %zd bytes",
		    sizeof(*up));
		goto error;
	}

	up->fd = fd;
	up->uf = uf;

	return (up);

error:
	if (fd > -1)
		close(fd);
	if (up != NULL)
		free(up);
	return NULL;

}

void
usbpcap_close(usbpcap_t *up)
{
	if (up == NULL)
		return;
	if (up->fd > 0)
		close(up->fd);
	up->fd = -1;
	free(up);
}

void
usbpcap_print_urbpf_header(const usbpf_urb_t *ub)
{
	const struct usbpf_pkthdr *up = &ub->hdr;
	struct tm *tm;
	size_t len;
	char buf[64];

	tm = localtime(&ub->tv.tv_sec);

	len = strftime(buf, sizeof(buf), "%H:%M:%S", tm);

	printf("%.*s.%06ld usbus%d.%d %s-%s-EP=%08x,SPD=%s,NFR=%d,SLEN=%d,IVAL=%d%s%s\n",
	    (int)len, buf, ub->tv.tv_usec,
	    (int)up->up_busunit, (int)up->up_address,
	    (up->up_type == USBPF_XFERTAP_SUBMIT) ? "SUBM" : "DONE",
	    usb_xferstr(up->up_xfertype),
	    (unsigned int)up->up_endpoint,
	    usb_speedstr(up->up_speed),
	    (int)up->up_frames,
	    (int)(up->up_totlen - USBPF_HDR_LEN -
	    (USBPF_FRAME_HDR_LEN * up->up_frames)),
	    (int)up->up_interval,
	    (up->up_type == USBPF_XFERTAP_DONE) ? ",ERR=" : "",
	    (up->up_type == USBPF_XFERTAP_DONE) ?
	    usb_errstr(up->up_error) : "");
}

static void
usbpcap_handle_usb_frame(usbpcap_t *uh, const struct header_32 *hdr,
    const uint8_t *ptr, int ptr_len)
{

	//printf("  usb frame: %d bytes\n", ptr_len);

	struct usbpf_pkthdr up_temp;
	struct usbpf_pkthdr *up;
	usbpf_urb_t *urb = NULL;
	uint32_t x;

	ptr += USBPF_HDR_LEN;
	ptr_len -= USBPF_HDR_LEN;
	if (ptr_len < 0)
		return;

	/* make sure we don't change the source buffer */
	memcpy(&up_temp, ptr - USBPF_HDR_LEN, sizeof(up_temp));
	up = &up_temp;

	/* Parse the URB */

	up->up_totlen = le32toh(up->up_totlen);
	up->up_busunit = le32toh(up->up_busunit);
	up->up_flags = le32toh(up->up_flags);
	up->up_status = le32toh(up->up_status);
	up->up_error = le32toh(up->up_error);
	up->up_interval = le32toh(up->up_interval);
	up->up_frames = le32toh(up->up_frames);
	up->up_packet_size = le32toh(up->up_packet_size);
	up->up_packet_count = le32toh(up->up_packet_count);
	up->up_endpoint = le32toh(up->up_endpoint);

	/*
	 * Create the urb representation to pass to the callback
	 */
	urb = usb_urb_create(up->up_frames);
	if (urb == NULL)
		goto error;
	/* XXX methodize */
	urb->hdr = *up;
	urb->tv.tv_sec = hdr->ts_sec;
	urb->tv.tv_usec = hdr->ts_usec;

	/* Parse any buffers, data or otherwise */

	for (x = 0; x != up->up_frames; x++) {
		const struct usbpf_framehdr *uf;
		uint32_t framelen = 0;
		uint32_t flags;
		const uint8_t *buf = NULL;
		int tot_frame_len = 0;

		uf = (const struct usbpf_framehdr *)ptr;
		ptr += USBPF_FRAME_HDR_LEN;
		ptr_len -= USBPF_FRAME_HDR_LEN;
		if (ptr_len < 0)
			goto error;

		framelen = le32toh(uf->length);
		flags = le32toh(uf->flags);

#if 0
		printf(" frame[%u] %s %d bytes\n",
		    (unsigned int)x,
		    (flags & USBPF_FRAMEFLAG_READ) ? "READ" : "WRITE",
		    (int)framelen);
#endif

		if (flags & USBPF_FRAMEFLAG_DATA_FOLLOWS) {

			tot_frame_len = USBPF_FRAME_ALIGN(framelen);
			ptr_len -= tot_frame_len;

			if (tot_frame_len < 0 ||
			    (int)framelen < 0 || (int)ptr_len < 0)
				break;

			buf = ptr;
			ptr += tot_frame_len;
		}

		/* Populate our buffer, with optional data */
		usbpf_frame_payload_t *ufp =
		    usb_frame_payload_create(tot_frame_len);
		if (ufp == NULL)
			goto error;

		/* XXX methodize */
		ufp->ep_id = up->up_endpoint;
		ufp->frame_id = x;
		ufp->flags = flags;
		ufp->frame_length = framelen;
		if (buf != NULL)
			memcpy(ufp->buf, buf, tot_frame_len);

		usb_frame_payload_list_add(urb->payloads, ufp, x);
	}

	/* Call our callback */
	if (uh->iter_cb != NULL)
		(uh->iter_cb)(uh, urb);
	else
		usb_urb_free(urb);

	return;

error:
	if (urb != NULL)
		usb_urb_free(urb);
	return;
}

static void
usbpcap_handle_packet(usbpcap_t *up, uint8_t *data, int datalen)
{
	//printf("Read packet: %d bytes\n", datalen);

	struct header_32 temp;
	uint8_t *ptr;
	uint8_t *next;

	for (ptr = data; ptr < (data + datalen); ptr = next) {

		const struct header_32 *hdr32;

		hdr32 = (const struct header_32 *)ptr;

		temp.ts_sec = le32toh(hdr32->ts_sec);
		temp.ts_usec = le32toh(hdr32->ts_usec);
		temp.caplen = le32toh(hdr32->caplen);
		temp.datalen = le32toh(hdr32->datalen);
		temp.hdrlen = hdr32->hdrlen;
		temp.align = hdr32->align;

		next = ptr + roundup2(temp.hdrlen + temp.caplen, temp.align);

		usbpcap_handle_usb_frame(up, &temp,
		    ptr + temp.hdrlen, temp.caplen);

		if (next <= ptr)
			err(EXIT_FAILURE, "Invalid length");
	}
}

void
usbpcap_iterate_frames(usbpcap_t *up)
{
	int ret;
	int datalen;

	/* Read packet loop */
	while ((ret = read(up->fd, &datalen, sizeof(int))) == sizeof(int)) {
		uint8_t *data;
		datalen = le32toh(datalen);
		data = malloc(datalen);
		if (data == NULL)
			errx(EX_SOFTWARE, "Out of memory.");

		ret = read(up->fd, data, datalen);
		if (ret != datalen) {
			fprintf(stderr, "Could not read complete "
			    "USB data payload");
			return;
		}

		usbpcap_handle_packet(up, data, datalen);
		free(data);
	}
}

usbpf_urb_t *
usb_urb_create(int nframes)
{
	usbpf_urb_t *urb = NULL;

	urb = calloc(1, sizeof(*urb));
	if (urb == NULL) {
		warn("%s: calloc failed (%zd bytes)", __func__, sizeof(urb));
		goto error;
	}

	urb->payloads = usb_frame_payload_list_create(nframes);
	if (urb->payloads == NULL) {
		fprintf(stderr, "%s: failed to create frame payload list\n",
		    __func__);
		goto error;
	}

	return urb;

error:
	if (urb != NULL) {
		usb_urb_free(urb);
	}
	return (NULL);
}

void
usb_urb_free(usbpf_urb_t *urb)
{

	if (urb == NULL)
		return;

	if (urb->payloads != NULL) {
		usb_frame_payload_list_free(urb->payloads);
		urb->payloads = NULL;
	}
	free(urb);
}

usbpf_frame_payload_list_t *
usb_frame_payload_list_create(int nframes)
{
	usbpf_frame_payload_list_t *ul = NULL;

	ul = calloc(1, sizeof(*ul));
	if (ul == NULL) {
		warn("%s: calloc failed (%zd bytes)", __func__, sizeof(*ul));
		goto error;
	}

	ul->num_frames = nframes;
	ul->frame_array = calloc(nframes, sizeof(usbpf_frame_payload_t *));
	if (ul->frame_array == NULL) {
		fprintf(stderr, "%s: failed to create frame payload list\n",
		    __func__);
		goto error;
	}

	return (ul);

error:
	if (ul != NULL)
		usb_frame_payload_list_free(ul);
	return (NULL);
}

void
usb_frame_payload_list_free(usbpf_frame_payload_list_t *ul)
{
	int i;

	if (ul == NULL)
		return;

	for (i = 0; i < ul->num_frames; i++) {
		if (ul->frame_array[i] == NULL)
			continue;
		usb_frame_payload_free(ul->frame_array[i]);
		ul->frame_array[i] = NULL;
	}

	free(ul);
}

usbpf_frame_payload_t *
usb_frame_payload_create(int buf_len)
{
	usbpf_frame_payload_t *ub = NULL;

	ub = calloc(1, sizeof(*ub));
	if (ub == NULL) {
		warn("%s: failed to allocate %zd bytes",
		    __func__, sizeof(*ub));
		goto error;
	}
	if (buf_len > 0) {
		ub->buf = calloc(buf_len, sizeof(uint8_t));
		if (ub->buf == NULL) {
			warn("%s: failed to allocate %zd bytes",
			    __func__, sizeof(*ub));
			goto error;
		}
		ub->buf_length = buf_len;
	}

	return (ub);

error:
	if (ub != NULL)
		usb_frame_payload_free(ub);

	return (NULL);
}

void
usb_frame_payload_free(usbpf_frame_payload_t *ub)
{
	if (ub == NULL)
		return;

	if (ub->buf != NULL)
		free(ub->buf);
	free(ub);
}

bool
usb_frame_payload_list_add(usbpf_frame_payload_list_t *ul,
    usbpf_frame_payload_t *uf, int frame_id)
{
	if (ul == NULL)
		return (false);

	if (frame_id >= ul->num_frames)
		return (false);

	if (ul->frame_array[frame_id] != NULL) {
		usb_frame_payload_free(ul->frame_array[frame_id]);
		ul->frame_array = NULL;
	}

	ul->frame_array[frame_id] = uf;
	return (true);
}
