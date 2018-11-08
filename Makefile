.PHONE: clean

CFLAGS+=-std=c99 -O2 -D_GNU_SOURCE -Iinclude -W -Wall -pedantic		\
	-Wundef -Wendif-labels -Wshadow -Wpointer-arith -Wcast-align	\
	-Wcast-qual -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes \
	-Wnested-externs -Winline -Wdisabled-optimization

EXE=barrierd client

HEADERS=include/barrierd.h	\
	attach.h 		\
	drop.h			\
	ebpf_state.h		\
	libbpf-macros.h		\
	map.h			\
	setup.h

OBJECTS=attach.o barrierd.o drop.o map.o setup.o
SCRIPTS=signal.epbf.inc

all: $(EXE)

client: samples/client.c include/barrierd.h
	$(CC) $(CFLAGS) samples/client.c -o client

barrierd: $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o barrierd -lseccomp

%.o: %.c $(HEADERS) $(SCRIPTS)
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *~ *.dSYM $(EXE) $(OBJECTS)