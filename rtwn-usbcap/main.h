#ifndef	__MAIN_H__
#define	__MAIN_H__


typedef struct rtwn_app rtwn_app_t;

typedef int usb_chipset_rx_buf_align(rtwn_app_t *ra, int pkt_len,
    int usb_frame_len);
typedef void usb_chipset_rx_decode(rtwn_app_t *ra, const uint8_t *buf,
    int len);

struct usb_chipset_ops {
	usb_chipset_rx_buf_align *rx_align;
	usb_chipset_rx_decode *rx_decode;
};

struct rtwn_app {
	struct usb_chipset_ops *ops;
	usbpcap_t *up;
};

extern	void chipset_rtl8812_init(rtwn_app_t *ra);
extern	void chipset_rtl8192_init(rtwn_app_t *ra);

#endif	/* __MAIN_H__ */
