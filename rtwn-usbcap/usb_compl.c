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
#include "usb_compl.h"

#define	USBPF_URB_COMPLETION_CACHE	32

static usbpf_urb_t *usb_compl[USBPF_URB_COMPLETION_CACHE] = { 0 };

void
usb_compl_init(void)
{

	memset(&usb_compl, 0, sizeof(usb_compl));
}

void
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
bool
usb_compl_lookup(int epid)
{
	int i;

	for (i = 0; i < USBPF_URB_COMPLETION_CACHE; i++) {
		if (usb_compl[i] != NULL &&
		    usb_compl[i]->hdr.up_endpoint == epid)
			return true;
	}
	return (false);
}

/*
 * Lookup, do remove and return it.
 * Return NULL if it's not found.
 */
usbpf_urb_t *
usb_compl_fetch(int epid)
{
	int i;

	for (i = 0; i < USBPF_URB_COMPLETION_CACHE; i++) {
		if (usb_compl[i] != NULL &&
		    usb_compl[i]->hdr.up_endpoint == epid) {
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
bool
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

