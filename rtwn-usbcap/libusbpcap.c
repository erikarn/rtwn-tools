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
