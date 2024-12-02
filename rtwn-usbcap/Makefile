CFLAGS=-Wall -Werror -g

default: rtwn-usbpcap

all: default

OBJS=main.o libusbpcap.o chipset_rtl8192.o chipset_rtl8812.o usb_compl.o

rtwn-usbpcap: $(OBJS)
	$(CC) -o rtwn-usbpcap $(OBJS)

clean:
	rm -f *.o rtwn-usbpcap
