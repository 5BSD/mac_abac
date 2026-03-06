/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Device Interface
 *
 * Provides /dev/vlabel character device for userland interaction:
 * - ioctl for mode control and statistics
 * - Future: rule loading, audit event delivery
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/uio.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

static d_open_t		vlabel_dev_open;
static d_close_t	vlabel_dev_close;
static d_ioctl_t	vlabel_dev_ioctl;

static struct cdevsw vlabel_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	vlabel_dev_open,
	.d_close =	vlabel_dev_close,
	.d_ioctl =	vlabel_dev_ioctl,
	.d_name =	"vlabel",
};

static struct cdev *vlabel_dev;

/*
 * Device open - only root can open
 */
static int
vlabel_dev_open(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td)
{
	int error;

	/* Require root privileges */
	error = priv_check(td, PRIV_MAC_PARTITION);
	if (error != 0) {
		VLABEL_DPRINTF("dev_open: permission denied for uid %d",
		    td->td_ucred->cr_uid);
		return (error);
	}

	VLABEL_DPRINTF("dev_open: opened by uid %d", td->td_ucred->cr_uid);
	return (0);
}

/*
 * Device close
 */
static int
vlabel_dev_close(struct cdev *dev __unused, int fflag __unused,
    int devtype __unused, struct thread *td __unused)
{

	VLABEL_DPRINTF("dev_close");
	return (0);
}

/*
 * Device ioctl - main control interface
 */
static int
vlabel_dev_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td)
{
	struct vlabel_stats *stats;
	int *modep;
	int error;

	/* All ioctls require root */
	error = priv_check(td, PRIV_MAC_PARTITION);
	if (error != 0)
		return (error);

	switch (cmd) {
	case VLABEL_IOC_GETMODE:
		modep = (int *)data;
		*modep = vlabel_mode;
		VLABEL_DPRINTF("ioctl GETMODE: %d", vlabel_mode);
		return (0);

	case VLABEL_IOC_SETMODE:
		modep = (int *)data;
		if (*modep < VLABEL_MODE_DISABLED ||
		    *modep > VLABEL_MODE_ENFORCING) {
			return (EINVAL);
		}
		VLABEL_DPRINTF("ioctl SETMODE: %d -> %d", vlabel_mode, *modep);
		vlabel_mode = *modep;
		return (0);

	case VLABEL_IOC_GETSTATS:
		stats = (struct vlabel_stats *)data;
		/* TODO: populate from actual counters */
		stats->vs_checks = 0;		/* Would need extern access */
		stats->vs_allowed = 0;
		stats->vs_denied = 0;
		stats->vs_labels_read = 0;
		stats->vs_labels_default = 0;
		stats->vs_rule_count = 0;
		VLABEL_DPRINTF("ioctl GETSTATS");
		return (0);

	case VLABEL_IOC_SETAUDIT:
		modep = (int *)data;
		if (*modep < VLABEL_AUDIT_NONE ||
		    *modep > VLABEL_AUDIT_VERBOSE) {
			return (EINVAL);
		}
		VLABEL_DPRINTF("ioctl SETAUDIT: %d -> %d",
		    vlabel_audit_level, *modep);
		vlabel_audit_level = *modep;
		return (0);

	default:
		VLABEL_DPRINTF("ioctl: unknown cmd 0x%lx", cmd);
		return (ENOTTY);
	}
}

/*
 * Initialize device interface
 */
void
vlabel_dev_init(void)
{

	vlabel_dev = make_dev(&vlabel_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "vlabel");
	if (vlabel_dev == NULL) {
		printf("vlabel: failed to create /dev/vlabel\n");
		return;
	}

	VLABEL_DPRINTF("created /dev/vlabel");
}

/*
 * Destroy device interface
 */
void
vlabel_dev_destroy(void)
{

	if (vlabel_dev != NULL) {
		destroy_dev(vlabel_dev);
		vlabel_dev = NULL;
		VLABEL_DPRINTF("destroyed /dev/vlabel");
	}
}
