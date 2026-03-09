# vLabel tools Makefile

CC=		cc
CFLAGS=		-O2 -pipe -Wall -Wextra -Werror -Wno-unused-parameter
CFLAGS+=	-I../kernel -I../daemon
CFLAGS+=	-I/usr/include/private/ucl

# Link against UCL for policy file parsing
LDADD=		-lprivateucl

PROGS=		vlabelctl

# vlabelctl source files (split for maintainability)
VLABELCTL_SRCS=	vlabelctl.c vlabelctl_rule.c vlabelctl_label.c
VLABELCTL_OBJS=	$(VLABELCTL_SRCS:.c=.o) ../daemon/parse_line.o ../daemon/parse_ucl.o

all: $(PROGS)

vlabelctl: $(VLABELCTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $(VLABELCTL_OBJS) $(LDADD)

vlabelctl.o: vlabelctl.c vlabelctl.h ../kernel/mac_vlabel.h
	$(CC) $(CFLAGS) -c vlabelctl.c

vlabelctl_rule.o: vlabelctl_rule.c vlabelctl.h ../kernel/mac_vlabel.h ../daemon/vlabeld.h
	$(CC) $(CFLAGS) -c vlabelctl_rule.c

vlabelctl_label.o: vlabelctl_label.c vlabelctl.h ../kernel/mac_vlabel.h
	$(CC) $(CFLAGS) -c vlabelctl_label.c

../daemon/parse_line.o:
	$(MAKE) -C ../daemon parse_line.o

../daemon/parse_ucl.o:
	$(MAKE) -C ../daemon parse_ucl.o

clean:
	rm -f $(PROGS) *.o

.PHONY: all clean
