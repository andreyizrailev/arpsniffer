CC=gcc
CFLAGS=-Wall
LDFLAGS=-lpcap
HEADERS=mac_vendor.h oui_array.h
SOURCES=arpsniffer.c mac_vendor.c

all: arpsniffer

oui_array.h: oui.txt handle_oui.sh
	./handle_oui.sh

arpsniffer: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS)

clean:
	rm -f arpsniffer oui_array.h
