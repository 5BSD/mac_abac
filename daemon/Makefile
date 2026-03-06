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

${PROG}: ${SRCS}
	${CC} ${CFLAGS} ${LDFLAGS} -o ${PROG} ${SRCS} ${LDADD}

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
