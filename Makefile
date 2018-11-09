.PHONY: clean format tidy

TIDY ?= clang-tidy

CFLAGS+=-std=c99 -O2 -g -ggdb -D_GNU_SOURCE -Iinclude -W -Wall -pedantic     \
	-Wundef -Wendif-labels -Wshadow -Wpointer-arith -Wcast-align	     \
	-Wcast-qual -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes \
	-Wnested-externs -Winline -Wdisabled-optimization

EXE=barrierd client

HEADERS=include/barrierd.h	\
	attach.h 		\
	drop.h			\
	ebpf_state.h		\
	libbpf-macros.h		\
	line_iterator.h		\
	map.h			\
	parse_stat.h		\
	setup.h

GENERATED=notice.c

OBJECTS=attach.o		\
	barrierd.o		\
	drop.o			\
	notice.o		\
	line_iterator.o		\
	map.o			\
	parse_stat.o		\
	setup.o

SCRIPTS=signal.epbf.inc

all: $(EXE)

client: samples/client.c include/barrierd.h
	$(CC) $(CFLAGS) samples/client.c -o client

barrierd: $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o barrierd -static -lseccomp

%.o: %.c $(HEADERS) $(SCRIPTS)
	$(CC) $(CFLAGS) -c $<

notice.o: NOTICE
	@echo "Generating $@"
	xxd -i NOTICE > notice.c
	$(CC) -c notice.c

clean:
	rm -rf *~ *.dSYM $(EXE) $(GENERATED) $(OBJECTS)

format:
	clang-format -i *.c $(HEADERS)

tidy:
	$(TIDY) *.c $(HEADERS) -- $(CFLAGS) -Wno-missing-field-initializers
