# vLabel tools Makefile

CC=		cc
CFLAGS=		-O2 -pipe -Wall -Wextra -Werror -Wno-unused-parameter
CFLAGS+=	-I../kernel -I../daemon

PROGS=		vlabelctl

# vlabelctl needs parse_line.o from daemon
VLABELCTL_OBJS=	vlabelctl.o ../daemon/parse_line.o

all: $(PROGS)

vlabelctl: $(VLABELCTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $(VLABELCTL_OBJS)

vlabelctl.o: vlabelctl.c ../kernel/mac_vlabel.h ../daemon/vlabeld.h
	$(CC) $(CFLAGS) -c vlabelctl.c

../daemon/parse_line.o:
	$(MAKE) -C ../daemon parse_line.o

clean:
	rm -f $(PROGS) *.o

.PHONY: all clean
