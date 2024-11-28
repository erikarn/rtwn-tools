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
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sysexits.h>
#include <err.h>

/*
 * XXX TODO: these should be in a header!
 */

struct usbcap_filehdr {
	uint32_t	magic;
#define USBCAP_FILEHDR_MAGIC    0x9a90000e
	uint8_t	 major;
	uint8_t	 minor;
	uint8_t	 reserved[26];
} __packed;

struct header_32 {
	/* capture timestamp */
	uint32_t ts_sec;
	uint32_t ts_usec;
	/* data length and alignment information */
	uint32_t caplen;
	uint32_t datalen;
	uint8_t hdrlen;
	uint8_t align;
} __packed;

#define USB_XFERTYPE_MAX 4

static const char *xfertype_table[USB_XFERTYPE_MAX] = {
        [UE_CONTROL]                    = "CTRL",
        [UE_ISOCHRONOUS]                = "ISOC",
        [UE_BULK]                       = "BULK",
        [UE_INTERRUPT]                  = "INTR"
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
        [USB_ERR_NOT_STARTED]           = "NOT_STARTED",
        [USB_ERR_INVAL]                 = "INVAL",
        [USB_ERR_NOMEM]                 = "NOMEM",
        [USB_ERR_CANCELLED]             = "CANCELLED",
        [USB_ERR_BAD_ADDRESS]           = "BAD_ADDRESS",
        [USB_ERR_BAD_BUFSIZE]           = "BAD_BUFSIZE",
        [USB_ERR_BAD_FLAG]              = "BAD_FLAG",
        [USB_ERR_NO_CALLBACK]           = "NO_CALLBACK",
        [USB_ERR_IN_USE]                = "IN_USE",
        [USB_ERR_NO_ADDR]               = "NO_ADDR",
        [USB_ERR_NO_PIPE]               = "NO_PIPE",
        [USB_ERR_ZERO_NFRAMES]          = "ZERO_NFRAMES",
        [USB_ERR_ZERO_MAXP]             = "ZERO_MAXP",
        [USB_ERR_SET_ADDR_FAILED]       = "SET_ADDR_FAILED",
        [USB_ERR_NO_POWER]              = "NO_POWER",
        [USB_ERR_TOO_DEEP]              = "TOO_DEEP",
        [USB_ERR_IOERROR]               = "IOERROR",
        [USB_ERR_NOT_CONFIGURED]        = "NOT_CONFIGURED",
        [USB_ERR_TIMEOUT]               = "TIMEOUT",
        [USB_ERR_SHORT_XFER]            = "SHORT_XFER",
        [USB_ERR_STALLED]               = "STALLED",
        [USB_ERR_INTERRUPTED]           = "INTERRUPTED",
        [USB_ERR_DMA_LOAD_FAILED]       = "DMA_LOAD_FAILED",
        [USB_ERR_BAD_CONTEXT]           = "BAD_CONTEXT",
        [USB_ERR_NO_ROOT_HUB]           = "NO_ROOT_HUB",
        [USB_ERR_NO_INTR_THREAD]        = "NO_INTR_THREAD",
        [USB_ERR_NOT_LOCKED]            = "NOT_LOCKED",
};


static const char *
usb_errstr(uint32_t error)
{
        if (error >= USB_ERR_MAX || errstr_table[error] == NULL)
                return ("UNKNOWN");
        else
                return (errstr_table[error]);
}

static const char *
usb_speedstr(uint8_t speed)
{
        if (speed >= USB_SPEED_MAX  || speed_table[speed] == NULL)
                return ("UNKNOWN");
        else
                return (speed_table[speed]);
}

static const char *
usb_xferstr(uint8_t type)
{
        if (type >= USB_XFERTYPE_MAX  || xfertype_table[type] == NULL)
                return ("UNKN");
        else
                return (xfertype_table[type]);
}

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

	if (ptr_len == 1)
		val = *(uint8_t *) ptr;
	else if (ptr_len == 2)
		val = le16toh(*(uint16_t *) ptr);
	else if (ptr_len == 4)
		val = le16toh(*(uint32_t *) ptr);
	else
		return;

	printf("  VAL: 0x%08x\n", val);
}

/*
 * This is a total hack; ideally we'd be passing the stack of subframes
 * in as a list so I can parse it.  But since this is purely going to be
 * used for initial register IO, I can totally fake it here.
 */
static void
handle_usb_subframe(const struct usbpf_pkthdr *up, int x, const uint8_t *ptr, int ptr_len)
{
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
}

static void
handle_usb_frame(const struct header_32 *hdr, const uint8_t *ptr, int ptr_len)
{
//	printf("  usb frame: %d bytes\n", ptr_len);

        struct usbpf_pkthdr up_temp;
        struct timeval tv;
        struct tm *tm;
        struct usbpf_pkthdr *up;
        size_t len;
        uint32_t x;
        char buf[64];

        ptr += USBPF_HDR_LEN;
        ptr_len -= USBPF_HDR_LEN;
        if (ptr_len < 0)
                return;
        /* make sure we don't change the source buffer */
        memcpy(&up_temp, ptr - USBPF_HDR_LEN, sizeof(up_temp));
        up = &up_temp;

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

        tv.tv_sec = hdr->ts_sec;
        tv.tv_usec = hdr->ts_usec;
        tm = localtime(&tv.tv_sec);

        len = strftime(buf, sizeof(buf), "%H:%M:%S", tm);


	printf("%.*s.%06ld usbus%d.%d %s-%s-EP=%08x,SPD=%s,NFR=%d,SLEN=%d,IVAL=%d%s%s\n",
	    (int)len, buf, tv.tv_usec,
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

	for (x = 0; x != up->up_frames; x++) {
		const struct usbpf_framehdr *uf;
		uint32_t framelen;
		uint32_t flags;

		uf = (const struct usbpf_framehdr *)ptr;
		ptr += USBPF_FRAME_HDR_LEN;
		ptr_len -= USBPF_FRAME_HDR_LEN;
		if (ptr_len < 0)
			return;

		framelen = le32toh(uf->length);
		flags = le32toh(uf->flags);

		printf(" frame[%u] %s %d bytes\n",
		    (unsigned int)x,
		    (flags & USBPF_FRAMEFLAG_READ) ? "READ" : "WRITE",
		    (int)framelen);

		if (flags & USBPF_FRAMEFLAG_DATA_FOLLOWS) {
			int tot_frame_len;

			tot_frame_len = USBPF_FRAME_ALIGN(framelen);
			ptr_len -= tot_frame_len;

			if (tot_frame_len < 0 ||
			    (int)framelen < 0 || (int)ptr_len < 0)
				break;

			handle_usb_subframe(up, x, ptr, framelen);
			ptr += tot_frame_len;
		}
	}
}

static void
handle_packet(uint8_t *data, int datalen)
{
	printf("Read packet: %d bytes\n", datalen);

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

		handle_usb_frame(&temp, ptr + temp.hdrlen, temp.caplen);

		if (next <= ptr)
			err(EXIT_FAILURE, "Invalid length");
	}
}

int
main(int argc, const char *argv[])
{
	struct usbcap_filehdr uf;
	int fd;
	int ret;
	int datalen;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		err(EXIT_FAILURE, "Could not open '%s' for read", argv[1]);
	}

	/* Open file */
	ret = read(fd, &uf, sizeof(uf));

	/* Header validation */
	if (ret != sizeof(uf)) {
		err(EXIT_FAILURE, "Could not read USB capture file header");
	}
	if (le32toh(uf.magic) != USBCAP_FILEHDR_MAGIC) {
		errx(EX_SOFTWARE, "Invalid magic field (0x%08x) "
		    "in USB capture file header.",
		    (unsigned int) le32toh(uf.magic));
	}
	if (uf.major != 0) {
		errx(EX_SOFTWARE, "Invalid major version(%d) "
		    "field in USB capture file header.", (int)uf.major);
	}

	if (uf.minor != 3) {
		errx(EX_SOFTWARE, "Invalid minor version(%d) "
		    "field in USB capture file header.", (int)uf.minor);
	}

	/* Read packet loop */
	while ((ret = read(fd, &datalen, sizeof(int))) == sizeof(int)) {
		uint8_t *data;
		datalen = le32toh(datalen);
		data = malloc(datalen);
		if (data == NULL)
			errx(EX_SOFTWARE, "Out of memory.");

		ret = read(fd, data, datalen);
		if (ret != datalen) {
			err(EXIT_FAILURE, "Could not read complete "
			    "USB data payload");
		}

		handle_packet(data, datalen);
		free(data);
	}

	close(fd); fd = -1;
	exit(0);
}
