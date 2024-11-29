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

struct usbpf_frame_payload {
	int ep_id;
	int frame_id;
	uint32_t flags; /* USBPF_FRAMEFLAG_* */
	int frame_length;
	int buf_length;
	uint8_t *buf;
};
typedef struct usbpf_frame_payload usbpf_frame_payload_t;

struct usbpf_frame_payload_list {
	int num_frames;
	usbpf_frame_payload_t **frame_array;
};
typedef struct usbpf_frame_payload_list usbpf_frame_payload_list_t;

struct usbpf_urb {
	struct usbpf_pkthdr hdr;
	struct timeval tv;
	usbpf_frame_payload_list_t *payloads;
};
typedef struct usbpf_urb usbpf_urb_t;

typedef struct usbpcap usbpcap_t;

typedef void usbpcap_packet_iterate_callback_t(usbpcap_t *up,
	usbpf_urb_t *urb);

struct usbpcap {
	struct usbcap_filehdr uf;
	usbpcap_packet_iterate_callback_t *iter_cb;
	int fd;
};


extern	const char * usb_errstr(uint32_t error);
extern	const char * usb_speedstr(uint8_t speed);
extern	const char * usb_xferstr(uint8_t type);

extern	usbpf_frame_payload_t * usb_frame_payload_create(int buf_len);
extern	void usb_frame_payload_free(usbpf_frame_payload_t *uf);

extern	usbpf_frame_payload_list_t * usb_frame_payload_list_create(int nframes);
extern	bool usb_frame_payload_list_add(usbpf_frame_payload_list_t *ul,
	    usbpf_frame_payload_t *uf, int frame_id);
extern	void usb_frame_payload_list_free(usbpf_frame_payload_list_t *ul);

extern	usbpf_urb_t * usb_urb_create(int nframes);
extern	void usb_urb_free(usbpf_urb_t *urb);

extern	usbpcap_t * usbpcap_open(const char *filename);
extern	void usbpcap_close(usbpcap_t *up);

extern	void usbpcap_print_urbpf_header(const usbpf_urb_t *ub);

extern	void usbpcap_iterate_frames(usbpcap_t *up);

#endif	/* __LIBUSBPCAP_H__ */
