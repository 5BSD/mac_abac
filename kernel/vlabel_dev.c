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

#include <machine/atomic.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * Reference count for open device handles.
 * Prevents module unload while device is in use.
 */
static volatile u_int vlabel_dev_refcnt;

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

	/* Increment reference count to prevent module unload */
	atomic_add_int(&vlabel_dev_refcnt, 1);

	VLABEL_DPRINTF("dev_open: opened by uid %d (refcnt=%u)",
	    td->td_ucred->cr_uid, vlabel_dev_refcnt);
	return (0);
}

/*
 * Device close
 */
static int
vlabel_dev_close(struct cdev *dev __unused, int fflag __unused,
    int devtype __unused, struct thread *td __unused)
{

	/* Decrement reference count */
	atomic_subtract_int(&vlabel_dev_refcnt, 1);

	VLABEL_DPRINTF("dev_close (refcnt=%u)", vlabel_dev_refcnt);
	return (0);
}

/*
 * Convert rule_io from userland to kernel rule structure
 */
static void
vlabel_rule_from_io(struct vlabel_rule *rule, const struct vlabel_rule_io *io)
{

	rule->vr_id = io->vr_id;
	rule->vr_action = io->vr_action;
	rule->vr_operations = io->vr_operations;

	/* Copy subject pattern */
	rule->vr_subject.vp_flags = io->vr_subject.vp_flags;
	strlcpy(rule->vr_subject.vp_type, io->vr_subject.vp_type,
	    sizeof(rule->vr_subject.vp_type));
	strlcpy(rule->vr_subject.vp_domain, io->vr_subject.vp_domain,
	    sizeof(rule->vr_subject.vp_domain));
	strlcpy(rule->vr_subject.vp_name, io->vr_subject.vp_name,
	    sizeof(rule->vr_subject.vp_name));
	strlcpy(rule->vr_subject.vp_level, io->vr_subject.vp_level,
	    sizeof(rule->vr_subject.vp_level));

	/* Copy object pattern */
	rule->vr_object.vp_flags = io->vr_object.vp_flags;
	strlcpy(rule->vr_object.vp_type, io->vr_object.vp_type,
	    sizeof(rule->vr_object.vp_type));
	strlcpy(rule->vr_object.vp_domain, io->vr_object.vp_domain,
	    sizeof(rule->vr_object.vp_domain));
	strlcpy(rule->vr_object.vp_name, io->vr_object.vp_name,
	    sizeof(rule->vr_object.vp_name));
	strlcpy(rule->vr_object.vp_level, io->vr_object.vp_level,
	    sizeof(rule->vr_object.vp_level));

	/* Context not yet supported via ioctl */
	memset(&rule->vr_context, 0, sizeof(rule->vr_context));

	/* For TRANSITION rules, parse the new label */
	memset(&rule->vr_newlabel, 0, sizeof(rule->vr_newlabel));
	if (io->vr_action == VLABEL_ACTION_TRANSITION &&
	    io->vr_newlabel[0] != '\0') {
		vlabel_label_parse(io->vr_newlabel, strlen(io->vr_newlabel),
		    &rule->vr_newlabel);
	}
}

/*
 * Device ioctl - main control interface
 */
static int
vlabel_dev_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td)
{
	struct vlabel_stats *stats;
	struct vlabel_rule_io *rule_io;
	struct vlabel_rule rule;
	uint32_t *rule_id;
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
		vlabel_rules_get_stats(stats);
		VLABEL_DPRINTF("ioctl GETSTATS: checks=%ju denied=%ju rules=%u",
		    (uintmax_t)stats->vs_checks,
		    (uintmax_t)stats->vs_denied,
		    stats->vs_rule_count);
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

	case VLABEL_IOC_RULE_ADD:
		rule_io = (struct vlabel_rule_io *)data;
		vlabel_rule_from_io(&rule, rule_io);
		error = vlabel_rule_add(&rule);
		VLABEL_DPRINTF("ioctl RULE_ADD: id=%u action=%d ops=0x%x err=%d",
		    rule.vr_id, rule.vr_action, rule.vr_operations, error);
		return (error);

	case VLABEL_IOC_RULE_REMOVE:
		rule_id = (uint32_t *)data;
		error = vlabel_rule_remove(*rule_id);
		VLABEL_DPRINTF("ioctl RULE_REMOVE: id=%u err=%d", *rule_id, error);
		return (error);

	case VLABEL_IOC_RULES_CLEAR:
		vlabel_rules_clear();
		VLABEL_DPRINTF("ioctl RULES_CLEAR");
		return (0);

	default:
		VLABEL_DPRINTF("ioctl: unknown cmd 0x%lx", cmd);
		return (ENOTTY);
	}
}

/*
 * Check if device is in use (for module unload check)
 *
 * Returns true if device has open references, false otherwise.
 */
bool
vlabel_dev_in_use(void)
{

	return (vlabel_dev_refcnt > 0);
}

/*
 * Initialize device interface
 */
void
vlabel_dev_init(void)
{

	vlabel_dev_refcnt = 0;
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
