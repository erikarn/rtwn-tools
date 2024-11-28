
default: rtwn-usbpcap

all: default

OBJS=rtwn-usbpcap.o libusbpcap.o

rtwn-usbpcap: $(OBJS)
	$(CC) -o rtwn-usbpcap $(OBJS)

clean:
	rm -f *.o rtwn-usbpcap
