# vlabeld - vLabel Policy Daemon
#
# Uses FreeBSD base system's private UCL library

PROG=	vlabeld
SRCS=	vlabeld.c parse_ucl.c parse_line.c

# FreeBSD base system's private UCL library
CFLAGS+=	-I/usr/include/private/ucl
LDADD+=		-lprivateucl -lutil

# Warnings
CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-Wno-unused-parameter

# Debug build (uncomment for development)
# CFLAGS+=	-g -O0 -DDEBUG

# Install paths
PREFIX?=	/usr/local
BINDIR=		${PREFIX}/sbin
ETCDIR=		${PREFIX}/etc/vlabel

.PHONY: all clean install

all: ${PROG}

${PROG}: vlabeld.o parse_ucl.o parse_line.o
	${CC} ${CFLAGS} ${LDFLAGS} -o ${PROG} vlabeld.o parse_ucl.o parse_line.o ${LDADD}

vlabeld.o: vlabeld.c vlabeld.h ../kernel/mac_vlabel.h
	${CC} ${CFLAGS} -c vlabeld.c -o vlabeld.o

parse_ucl.o: parse_ucl.c vlabeld.h ../kernel/mac_vlabel.h
	${CC} ${CFLAGS} -c parse_ucl.c -o parse_ucl.o

parse_line.o: parse_line.c vlabeld.h ../kernel/mac_vlabel.h
	${CC} ${CFLAGS} -c parse_line.c -o parse_line.o

clean:
	rm -f ${PROG} *.o

install: ${PROG}
	install -d ${DESTDIR}${BINDIR}
	install -d ${DESTDIR}${ETCDIR}
	install -m 755 ${PROG} ${DESTDIR}${BINDIR}/
	@if [ ! -f ${DESTDIR}${ETCDIR}/policy.conf ]; then \
		install -m 644 ../etc/policy.conf.sample ${DESTDIR}${ETCDIR}/policy.conf; \
	fi
	@echo "Installed ${PROG} to ${DESTDIR}${BINDIR}/"
	@echo "Configuration directory: ${DESTDIR}${ETCDIR}/"
