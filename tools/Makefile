# ABAC tools Makefile

CC=		cc
CFLAGS=		-O2 -pipe -Wall -Wextra -Werror -Wno-unused-parameter
CFLAGS+=	-I../kernel -I../daemon
CFLAGS+=	-I/usr/include/private/ucl

# Link against UCL for policy file parsing
LDADD=		-lprivateucl

PROGS=		mac_abac_ctl

# mac_abac_ctl source files (split for maintainability)
ABACCTL_SRCS=	mac_abac_ctl.c mac_abac_ctl_rule.c mac_abac_ctl_label.c mac_abac_ctl_set.c
ABACCTL_OBJS=	$(ABACCTL_SRCS:.c=.o) ../daemon/parse_line.o ../daemon/parse_ucl.o

all: $(PROGS)

mac_abac_ctl: $(ABACCTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $(ABACCTL_OBJS) $(LDADD)

mac_abac_ctl.o: mac_abac_ctl.c mac_abac_ctl.h ../kernel/mac_abac.h
	$(CC) $(CFLAGS) -c mac_abac_ctl.c

mac_abac_ctl_rule.o: mac_abac_ctl_rule.c mac_abac_ctl.h ../kernel/mac_abac.h ../daemon/mac_abacd.h
	$(CC) $(CFLAGS) -c mac_abac_ctl_rule.c

mac_abac_ctl_label.o: mac_abac_ctl_label.c mac_abac_ctl.h ../kernel/mac_abac.h
	$(CC) $(CFLAGS) -c mac_abac_ctl_label.c

mac_abac_ctl_set.o: mac_abac_ctl_set.c mac_abac_ctl.h ../kernel/mac_abac.h
	$(CC) $(CFLAGS) -c mac_abac_ctl_set.c

../daemon/parse_line.o:
	$(MAKE) -C ../daemon parse_line.o

../daemon/parse_ucl.o:
	$(MAKE) -C ../daemon parse_ucl.o

clean:
	rm -f $(PROGS) *.o

.PHONY: all clean
