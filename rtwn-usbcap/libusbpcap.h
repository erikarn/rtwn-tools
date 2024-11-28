#ifndef	__LIBUSBPCAP_H__
#define	__LIBUSBPCAP_H__

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


extern	const char * usb_errstr(uint32_t error);
extern	const char * usb_speedstr(uint8_t speed);
extern	const char * usb_xferstr(uint8_t type);

#endif	/* __LIBUSBPCAP_H__ */
