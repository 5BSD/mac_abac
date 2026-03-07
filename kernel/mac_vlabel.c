/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel MAC Policy Module
 *
 * A label-based Mandatory Access Control policy for FreeBSD that stores
 * security labels in extended attributes and enforces access control
 * based on configurable rules.
 *
 * This file contains module registration, initialization, and the
 * mac_policy_ops structure. Implementation is split across:
 *   - vlabel_cred.c   - Credential label lifecycle and checks
 *   - vlabel_vnode.c  - Vnode label lifecycle and access checks
 *   - vlabel_proc.c   - Process checks and privilege grant
 *   - vlabel_label.c  - Label parsing and matching
 *   - vlabel_rules.c  - Rule engine
 *   - vlabel_dev.c    - /dev/vlabel device interface
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/extattr.h>
#include <sys/imgact.h>
#include <sys/acl.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * Global slot for storing our labels in MAC label structures
 */
int vlabel_slot;

/*
 * Configuration variables (exposed via sysctl)
 *
 * Note: These are accessed via sysctl which provides appropriate
 * synchronization. For check paths, stale reads are acceptable
 * as the mode change will eventually be visible.
 */
int vlabel_enabled = 1;
int vlabel_mode = VLABEL_MODE_PERMISSIVE;	/* Start permissive for safety */
int vlabel_audit_level = VLABEL_AUDIT_DENIALS;

/*
 * Configurable extended attribute name.
 *
 * Default is "vlabel" but can be changed to match other tools like
 * FreeBSDKit's maclabel tool (e.g., "mac_labels", "mac_policy").
 *
 * Note: Changing this while labels are in use may cause access issues.
 * Only change at boot via loader.conf or before loading policy rules.
 */
char vlabel_extattr_name[64] = VLABEL_EXTATTR_NAME;

/*
 * Initialization flag - set only after all subsystems are ready.
 * This prevents hooks from being called before locks are initialized.
 */
int vlabel_initialized = 0;

/*
 * Default labels for unlabeled objects/subjects
 */
struct vlabel_label vlabel_default_object;
struct vlabel_label vlabel_default_subject;

/*
 * Statistics - accessed atomically via atomic_add_64()
 */
uint64_t vlabel_labels_read;
uint64_t vlabel_labels_default;

/*
 * SYSCTL tree: security.mac.vlabel.*
 */
SYSCTL_DECL(_security_mac);
SYSCTL_NODE(_security_mac, OID_AUTO, vlabel, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "vLabel MAC policy");

SYSCTL_INT(_security_mac_vlabel, OID_AUTO, enabled, CTLFLAG_RW,
    &vlabel_enabled, 0, "Enable vLabel MAC policy");

SYSCTL_INT(_security_mac_vlabel, OID_AUTO, mode, CTLFLAG_RW,
    &vlabel_mode, 0, "Enforcement mode (0=disabled, 1=permissive, 2=enforcing)");

SYSCTL_INT(_security_mac_vlabel, OID_AUTO, audit_level, CTLFLAG_RW,
    &vlabel_audit_level, 0, "Audit level (0=none, 1=denials, 2=all, 3=verbose)");

SYSCTL_UQUAD(_security_mac_vlabel, OID_AUTO, labels_read, CTLFLAG_RD,
    &vlabel_labels_read, 0, "Labels read from extended attributes");

SYSCTL_UQUAD(_security_mac_vlabel, OID_AUTO, labels_default, CTLFLAG_RD,
    &vlabel_labels_default, 0, "Default labels assigned");

SYSCTL_STRING(_security_mac_vlabel, OID_AUTO, extattr_name, CTLFLAG_RW,
    vlabel_extattr_name, sizeof(vlabel_extattr_name),
    "Extended attribute name for labels (default: vlabel)");

/*
 * Policy lifecycle
 */
static void vlabel_destroy(struct mac_policy_conf *mpc);
static void vlabel_init(struct mac_policy_conf *mpc);
static int vlabel_syscall(struct thread *td, int call, void *arg);

/*
 * MAC policy operations structure
 */
static struct mac_policy_ops vlabel_ops = {
	/* Policy lifecycle */
	.mpo_destroy = vlabel_destroy,
	.mpo_init = vlabel_init,
	.mpo_syscall = vlabel_syscall,

	/* Credential label lifecycle */
	.mpo_cred_init_label = vlabel_cred_init_label,
	.mpo_cred_destroy_label = vlabel_cred_destroy_label,
	.mpo_cred_copy_label = vlabel_cred_copy_label,
	.mpo_cred_relabel = vlabel_cred_relabel,
	.mpo_cred_externalize_label = vlabel_cred_externalize_label,
	.mpo_cred_internalize_label = vlabel_cred_internalize_label,

	/* Credential checks */
	.mpo_cred_check_relabel = vlabel_cred_check_relabel,
	.mpo_cred_check_setuid = vlabel_cred_check_setuid,
	.mpo_cred_check_setgid = vlabel_cred_check_setgid,
	.mpo_cred_check_setgroups = vlabel_cred_check_setgroups,

	/* Process exec transition */
	.mpo_vnode_execve_transition = vlabel_execve_transition,
	.mpo_vnode_execve_will_transition = vlabel_execve_will_transition,

	/* Vnode label lifecycle */
	.mpo_vnode_init_label = vlabel_vnode_init_label,
	.mpo_vnode_destroy_label = vlabel_vnode_destroy_label,
	.mpo_vnode_copy_label = vlabel_vnode_copy_label,
	.mpo_vnode_associate_extattr = vlabel_vnode_associate_extattr,
	.mpo_vnode_create_extattr = vlabel_vnode_create_extattr,
	.mpo_vnode_setlabel_extattr = vlabel_vnode_setlabel_extattr,
	.mpo_vnode_relabel = vlabel_vnode_relabel,
	.mpo_vnode_externalize_label = vlabel_vnode_externalize_label,
	.mpo_vnode_internalize_label = vlabel_vnode_internalize_label,

	/* Vnode access checks */
	.mpo_vnode_check_access = vlabel_vnode_check_access,
	.mpo_vnode_check_chdir = vlabel_vnode_check_chdir,
	.mpo_vnode_check_chroot = vlabel_vnode_check_chroot,
	.mpo_vnode_check_create = vlabel_vnode_check_create,
	.mpo_vnode_check_deleteacl = vlabel_vnode_check_deleteacl,
	.mpo_vnode_check_deleteextattr = vlabel_vnode_check_deleteextattr,
	.mpo_vnode_check_exec = vlabel_vnode_check_exec,
	.mpo_vnode_check_getacl = vlabel_vnode_check_getacl,
	.mpo_vnode_check_getextattr = vlabel_vnode_check_getextattr,
	.mpo_vnode_check_link = vlabel_vnode_check_link,
	.mpo_vnode_check_listextattr = vlabel_vnode_check_listextattr,
	.mpo_vnode_check_lookup = vlabel_vnode_check_lookup,
	.mpo_vnode_check_mmap = vlabel_vnode_check_mmap,
	.mpo_vnode_check_open = vlabel_vnode_check_open,
	.mpo_vnode_check_poll = vlabel_vnode_check_poll,
	.mpo_vnode_check_read = vlabel_vnode_check_read,
	.mpo_vnode_check_readdir = vlabel_vnode_check_readdir,
	.mpo_vnode_check_readlink = vlabel_vnode_check_readlink,
	.mpo_vnode_check_relabel = vlabel_vnode_check_relabel,
	.mpo_vnode_check_rename_from = vlabel_vnode_check_rename_from,
	.mpo_vnode_check_rename_to = vlabel_vnode_check_rename_to,
	.mpo_vnode_check_revoke = vlabel_vnode_check_revoke,
	.mpo_vnode_check_setacl = vlabel_vnode_check_setacl,
	.mpo_vnode_check_setextattr = vlabel_vnode_check_setextattr,
	.mpo_vnode_check_setflags = vlabel_vnode_check_setflags,
	.mpo_vnode_check_setmode = vlabel_vnode_check_setmode,
	.mpo_vnode_check_setowner = vlabel_vnode_check_setowner,
	.mpo_vnode_check_setutimes = vlabel_vnode_check_setutimes,
	.mpo_vnode_check_stat = vlabel_vnode_check_stat,
	.mpo_vnode_check_unlink = vlabel_vnode_check_unlink,
	.mpo_vnode_check_write = vlabel_vnode_check_write,

	/* Mount label lifecycle */
	.mpo_mount_init_label = vlabel_mount_init_label,
	.mpo_mount_destroy_label = vlabel_mount_destroy_label,

	/* Process checks */
	.mpo_proc_check_debug = vlabel_proc_check_debug,
	.mpo_proc_check_sched = vlabel_proc_check_sched,
	.mpo_proc_check_signal = vlabel_proc_check_signal,

	/* Privilege grant */
	.mpo_priv_grant = vlabel_priv_grant,
};

/*
 * Policy lifecycle implementation
 */

static void
vlabel_init(struct mac_policy_conf *mpc)
{

	VLABEL_DPRINTF("initializing vLabel MAC policy");

	/* Initialize label subsystem (UMA zone) */
	vlabel_label_init();

	/* Initialize rule engine */
	vlabel_rules_init();

	/* Initialize audit subsystem */
	vlabel_audit_init();

	/* Initialize device interface */
	vlabel_dev_init();

	/* Initialize default labels */
	vlabel_label_set_default(&vlabel_default_object, false);
	vlabel_label_set_default(&vlabel_default_subject, true);

	/* Mark as initialized - hooks can now safely run */
	vlabel_initialized = 1;

	VLABEL_DPRINTF("vLabel MAC policy initialized (mode=%d)", vlabel_mode);
}

static void
vlabel_destroy(struct mac_policy_conf *mpc)
{

	VLABEL_DPRINTF("destroying vLabel MAC policy");

	/* Warn if device is still in use */
	if (vlabel_dev_in_use()) {
		printf("vlabel: WARNING: device still in use during unload\n");
	}

	/* Destroy device interface */
	vlabel_dev_destroy();

	/* Destroy audit subsystem */
	vlabel_audit_destroy();

	/* Destroy rule engine */
	vlabel_rules_destroy();

	/* Destroy label subsystem (UMA zone) */
	vlabel_label_destroy();

	VLABEL_DPRINTF("vLabel MAC policy destroyed");
}

static int
vlabel_syscall(struct thread *td, int call, void *arg)
{

	/* Reserved for future use */
	return (ENOSYS);
}

/*
 * Module registration
 *
 * We use NOTLATE because mpo_init calls uma_zcreate and make_dev which
 * can sleep. When loading late (after mac_late=1), mpo_init is called
 * with the MAC policy lock held and sleeping is not allowed.
 *
 * MPC_LOADTIME_FLAG_UNLOADOK - allows dynamic load/unload for development
 * For production, consider MPC_LOADTIME_FLAG_NOTLATE to prevent unloading
 */
MAC_POLICY_SET(&vlabel_ops, mac_vlabel, "vLabel MAC Policy",
    MPC_LOADTIME_FLAG_UNLOADOK, &vlabel_slot);
