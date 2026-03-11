# mac_abac MAC Policy Module Makefile
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
#   dtrace -n 'abac:::check-deny { printf("%s -> %s", stringof(arg0), stringof(arg1)); }'

.PATH: ${.CURDIR}

KMOD=	mac_abac
SRCS=	mac_abac.c abac_cred.c abac_vnode.c abac_proc.c abac_socket.c abac_pipe.c abac_posixshm.c abac_system.c
SRCS+=	abac_kenv.c abac_posixsem.c abac_sysv.c
SRCS+=	abac_label.c abac_match.c abac_rules.c abac_syscall.c
SRCS+=	mac_abac.h vnode_if.h

# Default warning level (can override with WARNS=6)
WARNS?=	3

# Include standard kernel module build infrastructure
.include <bsd.kmod.mk>
