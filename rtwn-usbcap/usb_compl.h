#ifndef	__USB_COMPL_H__
#define	__USB_COMPL_H__

extern	void usb_compl_init(void);
extern	void usb_compl_flush(void);
extern	bool usb_compl_lookup(int epid);
extern	usbpf_urb_t * usb_compl_fetch(int epid);
extern	bool usb_compl_add(usbpf_urb_t *urb);

#endif	/* __USB_COMPL_H__ */
