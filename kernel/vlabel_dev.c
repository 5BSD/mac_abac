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
#include <sys/poll.h>
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
static d_read_t		vlabel_dev_read;
static d_ioctl_t	vlabel_dev_ioctl;
static d_poll_t		vlabel_dev_poll;

static struct cdevsw vlabel_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	vlabel_dev_open,
	.d_close =	vlabel_dev_close,
	.d_read =	vlabel_dev_read,
	.d_ioctl =	vlabel_dev_ioctl,
	.d_poll =	vlabel_dev_poll,
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
 * Device read - read audit events
 */
static int
vlabel_dev_read(struct cdev *dev __unused, struct uio *uio, int ioflag)
{

	return (vlabel_audit_read(uio, ioflag));
}

/*
 * Device poll - poll for audit events
 */
static int
vlabel_dev_poll(struct cdev *dev __unused, int events, struct thread *td)
{

	return (vlabel_audit_poll(events, td));
}

/*
 * Convert rule_io from userland to kernel rule structure
 *
 * Returns 0 on success, error code on invalid input.
 */
static int
vlabel_rule_from_io(struct vlabel_rule *rule, const struct vlabel_rule_io *io)
{

	/* Validate action */
	if (io->vr_action > VLABEL_ACTION_TRANSITION) {
		VLABEL_DPRINTF("rule_from_io: invalid action %d", io->vr_action);
		return (EINVAL);
	}

	/* Validate operations - must have at least one operation */
	if (io->vr_operations == 0) {
		VLABEL_DPRINTF("rule_from_io: no operations specified");
		return (EINVAL);
	}

	/* Validate operations - only valid bits allowed */
	if ((io->vr_operations & ~VLABEL_OP_ALL) != 0) {
		VLABEL_DPRINTF("rule_from_io: invalid operations 0x%x",
		    io->vr_operations);
		return (EINVAL);
	}

	/* Validate rule ID - 0 is reserved */
	if (io->vr_id == 0) {
		VLABEL_DPRINTF("rule_from_io: rule ID 0 is reserved");
		return (EINVAL);
	}

	/* Validate context flags - only valid bits allowed */
	if ((io->vr_context.vc_flags & ~(VLABEL_CTX_CAP_SANDBOXED |
	    VLABEL_CTX_JAIL | VLABEL_CTX_UID | VLABEL_CTX_GID |
	    VLABEL_CTX_EUID | VLABEL_CTX_RUID | VLABEL_CTX_SID |
	    VLABEL_CTX_HAS_TTY | VLABEL_CTX_PARENT_LABEL)) != 0) {
		VLABEL_DPRINTF("rule_from_io: invalid context flags 0x%x",
		    io->vr_context.vc_flags);
		return (EINVAL);
	}

	rule->vr_id = io->vr_id;
	rule->vr_action = io->vr_action;
	rule->vr_operations = io->vr_operations;

	/* Parse subject pattern from pattern string */
	int error = vlabel_pattern_parse(io->vr_subject.vp_pattern,
	    strlen(io->vr_subject.vp_pattern), &rule->vr_subject);
	if (error != 0) {
		VLABEL_DPRINTF("rule_from_io: invalid subject pattern");
		return (error);
	}
	/* Preserve negate flag from io structure */
	if (io->vr_subject.vp_flags & VLABEL_MATCH_NEGATE)
		rule->vr_subject.vp_flags |= VLABEL_MATCH_NEGATE;

	/* Parse object pattern from pattern string */
	error = vlabel_pattern_parse(io->vr_object.vp_pattern,
	    strlen(io->vr_object.vp_pattern), &rule->vr_object);
	if (error != 0) {
		VLABEL_DPRINTF("rule_from_io: invalid object pattern");
		return (error);
	}
	/* Preserve negate flag from io structure */
	if (io->vr_object.vp_flags & VLABEL_MATCH_NEGATE)
		rule->vr_object.vp_flags |= VLABEL_MATCH_NEGATE;

	/* Copy context constraints */
	rule->vr_context.vc_flags = io->vr_context.vc_flags;
	rule->vr_context.vc_cap_sandboxed = io->vr_context.vc_cap_sandboxed;
	rule->vr_context.vc_has_tty = io->vr_context.vc_has_tty;
	rule->vr_context.vc_jail_check = io->vr_context.vc_jail_check;
	rule->vr_context.vc_uid = io->vr_context.vc_uid;
	rule->vr_context.vc_gid = io->vr_context.vc_gid;

	/* For TRANSITION rules, parse the new label */
	memset(&rule->vr_newlabel, 0, sizeof(rule->vr_newlabel));
	if (io->vr_action == VLABEL_ACTION_TRANSITION &&
	    io->vr_newlabel[0] != '\0') {
		vlabel_label_parse(io->vr_newlabel, strlen(io->vr_newlabel),
		    &rule->vr_newlabel);
	}

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
		error = vlabel_rule_from_io(&rule, rule_io);
		if (error != 0)
			return (error);
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

	case VLABEL_IOC_RULE_LIST:
		{
			struct vlabel_rule_list_io *list_io;
			struct vlabel_rule_io *kbuf;
			uint32_t max_rules, bufsize;

			list_io = (struct vlabel_rule_list_io *)data;
			max_rules = list_io->vrl_count;

			/* If no buffer provided, just return count */
			if (list_io->vrl_rules == NULL || max_rules == 0) {
				error = vlabel_rules_list(list_io, NULL, 0);
				VLABEL_DPRINTF("ioctl RULE_LIST: total=%u (query only)",
				    list_io->vrl_total);
				return (error);
			}

			/*
			 * Sanity limit - don't allocate huge buffers.
			 * 256 rules * ~808 bytes = ~206KB which is reasonable.
			 */
			if (max_rules > 256)
				max_rules = 256;
			bufsize = max_rules * sizeof(struct vlabel_rule_io);
			kbuf = malloc(bufsize, M_TEMP, M_NOWAIT | M_ZERO);
			if (kbuf == NULL)
				return (ENOMEM);

			/* Fill buffer with rules */
			error = vlabel_rules_list(list_io, kbuf, max_rules);
			if (error != 0) {
				free(kbuf, M_TEMP);
				return (error);
			}

			/* Copy rules to userland */
			error = copyout(kbuf, list_io->vrl_rules,
			    list_io->vrl_count * sizeof(struct vlabel_rule_io));

			free(kbuf, M_TEMP);

			VLABEL_DPRINTF("ioctl RULE_LIST: copied %u/%u rules",
			    list_io->vrl_count, list_io->vrl_total);
			return (error);
		}

	case VLABEL_IOC_GETAUDIT:
		modep = (int *)data;
		*modep = vlabel_audit_level;
		VLABEL_DPRINTF("ioctl GETAUDIT: %d", vlabel_audit_level);
		return (0);

	case VLABEL_IOC_TEST_ACCESS:
		{
			struct vlabel_test_io *test_io;

			test_io = (struct vlabel_test_io *)data;
			error = vlabel_rules_test_access(test_io);
			VLABEL_DPRINTF("ioctl TEST_ACCESS: result=%d rule=%u",
			    test_io->vt_result, test_io->vt_rule_id);
			return (error);
		}

	case VLABEL_IOC_GETDEFPOL:
		modep = (int *)data;
		*modep = vlabel_default_policy;
		VLABEL_DPRINTF("ioctl GETDEFPOL: %d", vlabel_default_policy);
		return (0);

	case VLABEL_IOC_SETDEFPOL:
		modep = (int *)data;
		if (*modep < 0 || *modep > 1)
			return (EINVAL);
		VLABEL_DPRINTF("ioctl SETDEFPOL: %d -> %d",
		    vlabel_default_policy, *modep);
		vlabel_default_policy = *modep;
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
 * Deferred device creation - called after devfs is ready
 *
 * Note: This is called via SYSINIT which may run multiple times if the
 * module is unloaded and reloaded. We use make_dev_s() with MAKEDEV_CHECKNAME
 * to safely handle the case where the device already exists.
 */
static void
vlabel_dev_create(void *arg __unused)
{
	struct make_dev_args args;
	int error;

	/* Skip if device already exists (module reload case) */
	if (vlabel_dev != NULL) {
		VLABEL_DPRINTF("device already exists, skipping creation");
		return;
	}

	make_dev_args_init(&args);
	args.mda_devsw = &vlabel_cdevsw;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0600;

	error = make_dev_s(&args, &vlabel_dev, "vlabel");
	if (error != 0) {
		printf("vlabel: failed to create /dev/vlabel: error %d\n", error);
		vlabel_dev = NULL;
		return;
	}

	VLABEL_DPRINTF("created /dev/vlabel");
}

/*
 * Wrapper for SYSUNINIT - matches required signature
 */
static void
vlabel_dev_destroy_sysuninit(void *arg __unused)
{

	vlabel_dev_destroy();
}

/*
 * Device creation is deferred to SI_SUB_DRIVERS because:
 * - MAC policies init at SI_SUB_MAC_POLICY (0x21C0000)
 * - devfs inits at SI_SUB_DEVFS (0x2F00000)
 * - SI_SUB_DRIVERS (0x3100000) is after devfs is ready
 *
 * We also register SYSUNINIT to clean up on module unload.
 */
SYSINIT(vlabel_dev, SI_SUB_DRIVERS, SI_ORDER_MIDDLE, vlabel_dev_create, NULL);
SYSUNINIT(vlabel_dev, SI_SUB_DRIVERS, SI_ORDER_MIDDLE, vlabel_dev_destroy_sysuninit, NULL);

/*
 * Initialize device interface - just init refcount, device created later
 */
void
vlabel_dev_init(void)
{

	vlabel_dev_refcnt = 0;
	/* Device creation deferred to SYSINIT after devfs is ready */
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
