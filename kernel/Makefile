# vLabel MAC Policy Module Makefile
#
# Build with: make
# Debug build: make VLABEL_DEBUG=1
# Install: make install (requires root)
#
# For out-of-tree building, set SYSDIR to your FreeBSD source tree:
#   make SYSDIR=/usr/src/sys
#
# To increase warning level for development:
#   make WARNS=6

.PATH: ${.CURDIR}

KMOD=	mac_vlabel
SRCS=	mac_vlabel.c mac_vlabel.h
SRCS+=	vnode_if.h

# Uncomment to enable debug output
#CFLAGS+= -DVLABEL_DEBUG

# Allow debug flag from command line
.if defined(VLABEL_DEBUG)
CFLAGS+= -DVLABEL_DEBUG
.endif

# Default warning level (can override with WARNS=6)
WARNS?=	3

# Include standard kernel module build infrastructure
.include <bsd.kmod.mk>
