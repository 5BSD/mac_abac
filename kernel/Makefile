# vLabel MAC Policy Module Makefile
#
# Build with: make
# Install: make install (requires root)
#
# For out-of-tree building, set SYSDIR to your FreeBSD source tree:
#   make SYSDIR=/usr/src/sys
#
# To increase warning level for development:
#   make WARNS=6
#
# Debugging: Use DTrace probes (see scripts/dtrace/)
#   dtrace -n 'vlabel:::check-deny { printf("%s -> %s", stringof(arg0), stringof(arg1)); }'

.PATH: ${.CURDIR}

KMOD=	mac_vlabel
SRCS=	mac_vlabel.c vlabel_cred.c vlabel_vnode.c vlabel_proc.c vlabel_socket.c vlabel_pipe.c vlabel_posixshm.c vlabel_system.c
SRCS+=	vlabel_kenv.c vlabel_posixsem.c vlabel_sysv.c
SRCS+=	vlabel_label.c vlabel_match.c vlabel_rules.c vlabel_syscall.c
SRCS+=	mac_vlabel.h vnode_if.h

# Default warning level (can override with WARNS=6)
WARNS?=	3

# Include standard kernel module build infrastructure
.include <bsd.kmod.mk>
