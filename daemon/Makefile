# mac_abacd - ABAC Policy Daemon
#
# Uses FreeBSD base system's private UCL library

PROG=	mac_abacd
SRCS=	mac_abacd.c parse_ucl.c parse_line.c

# FreeBSD base system's private UCL library
CFLAGS+=	-I/usr/include/private/ucl
LDADD+=		-lprivateucl -lutil

# Include kernel header
CFLAGS+=	-I../kernel

# Warnings
CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-Wno-unused-parameter

# Debug build (uncomment for development)
# CFLAGS+=	-g -O0 -DDEBUG

# Install paths
PREFIX?=	/usr/local
BINDIR=		${PREFIX}/sbin
ETCDIR=		${PREFIX}/etc/abac

.PHONY: all clean install

all: ${PROG}

${PROG}: mac_abacd.o parse_ucl.o parse_line.o
	${CC} ${CFLAGS} ${LDFLAGS} -o ${PROG} mac_abacd.o parse_ucl.o parse_line.o ${LDADD}

mac_abacd.o: mac_abacd.c mac_abacd.h ../kernel/mac_abac.h
	${CC} ${CFLAGS} -c mac_abacd.c -o mac_abacd.o

parse_ucl.o: parse_ucl.c mac_abacd.h ../kernel/mac_abac.h
	${CC} ${CFLAGS} -c parse_ucl.c -o parse_ucl.o

parse_line.o: parse_line.c mac_abacd.h ../kernel/mac_abac.h
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
