CC=gcc
CFLAGS=-Wall
LDFLAGS=-lpcap
HEADERS=
SOURCES=arpsniffer.c

all: arpsniffer

arpsniffer: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS)

clean:
	rm -f arpsniffer
