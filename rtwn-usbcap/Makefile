CFLAGS=-Wall -g

default: rtwn-usbpcap

all: default

OBJS=main.o libusbpcap.o

rtwn-usbpcap: $(OBJS)
	$(CC) -o rtwn-usbpcap $(OBJS)

clean:
	rm -f *.o rtwn-usbpcap
