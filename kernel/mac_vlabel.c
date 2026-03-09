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
 * This file contains module registration, initialization, syscall handler,
 * and the mac_policy_ops structure. Implementation is split across:
 *   - vlabel_cred.c   - Credential label lifecycle and checks
 *   - vlabel_vnode.c  - Vnode label lifecycle and access checks
 *   - vlabel_proc.c   - Process checks and privilege grant
 *   - vlabel_label.c  - Label parsing and matching
 *   - vlabel_rules.c  - Rule engine
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
#include "vlabel_dtrace.h"

/*
 * DTrace provider and probe definitions
 *
 * Provider: vlabel
 * Usage: dtrace -n 'vlabel:::check-deny { printf("%s", stringof(arg0)); }'
 */
SDT_PROVIDER_DEFINE(vlabel);

/* Access check probes */
SDT_PROBE_DEFINE3(vlabel, rules, check, entry,
    "char *",		/* subject label string */
    "char *",		/* object label string */
    "uint32_t");	/* operation bitmask */

SDT_PROBE_DEFINE2(vlabel, rules, check, return,
    "int",		/* result (0=allow, EACCES=deny) */
    "uint32_t");	/* operation bitmask */

SDT_PROBE_DEFINE4(vlabel, rules, check, allow,
    "char *",		/* subject label string */
    "char *",		/* object label string */
    "uint32_t",		/* operation bitmask */
    "uint32_t");	/* matching rule ID (0=default policy) */

SDT_PROBE_DEFINE4(vlabel, rules, check, deny,
    "char *",		/* subject label string */
    "char *",		/* object label string */
    "uint32_t",		/* operation bitmask */
    "uint32_t");	/* matching rule ID (0=default policy) */

/* Rule matching probes */
SDT_PROBE_DEFINE3(vlabel, rules, rule, match,
    "uint32_t",		/* rule ID */
    "uint8_t",		/* action (0=allow, 1=deny, 2=transition) */
    "uint32_t");	/* operation bitmask */

SDT_PROBE_DEFINE2(vlabel, rules, rule, nomatch,
    "int",		/* default policy (0=allow, 1=deny) */
    "uint32_t");	/* operation bitmask */

/* Label transition probes */
SDT_PROBE_DEFINE4(vlabel, cred, transition, exec,
    "char *",		/* old label string */
    "char *",		/* new label string */
    "char *",		/* executable label string */
    "pid_t");		/* pid */

/* Label read probes */
SDT_PROBE_DEFINE2(vlabel, label, extattr, read,
    "char *",		/* label string */
    "struct vnode *");	/* vnode pointer */

SDT_PROBE_DEFINE1(vlabel, label, extattr, default,
    "int");		/* is_subject (1=process, 0=file) */

/* Rule management probes */
SDT_PROBE_DEFINE3(vlabel, rules, rule, add,
    "uint32_t",		/* rule ID */
    "uint8_t",		/* action */
    "uint32_t");	/* operations bitmask */

SDT_PROBE_DEFINE1(vlabel, rules, rule, remove,
    "uint32_t");	/* rule ID */

SDT_PROBE_DEFINE1(vlabel, rules, rule, clear,
    "uint32_t");	/* count of rules cleared */

/* Mode change probes */
SDT_PROBE_DEFINE2(vlabel, policy, mode, change,
    "int",		/* old mode */
    "int");		/* new mode */

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
	.mpo_vnode_associate_singlelabel = vlabel_vnode_associate_singlelabel,
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

	/* Destroy rule engine */
	vlabel_rules_destroy();

	/* Destroy label subsystem (UMA zone) */
	vlabel_label_destroy();

	VLABEL_DPRINTF("vLabel MAC policy destroyed");
}

/*
 * mac_syscall handler - main control interface
 *
 * Called via: mac_syscall("vlabel", cmd, arg)
 * All commands require root.
 */
static int
vlabel_syscall(struct thread *td, int call, void *arg)
{
	int error, val;
	uint32_t rule_id;
	struct vlabel_stats stats;
	struct vlabel_rule_arg rule_arg;
	struct vlabel_rule_list_arg list_arg;
	struct vlabel_test_arg test_arg;
	char *data;
	size_t data_len;

	/* All commands require root */
	error = priv_check(td, PRIV_MAC_PARTITION);
	if (error)
		return (error);

	switch (call) {
	case VLABEL_SYS_GETMODE:
		error = copyout(&vlabel_mode, arg, sizeof(int));
		VLABEL_DPRINTF("syscall GETMODE: %d", vlabel_mode);
		break;

	case VLABEL_SYS_SETMODE:
		error = copyin(arg, &val, sizeof(int));
		if (error)
			break;
		if (val < VLABEL_MODE_DISABLED || val > VLABEL_MODE_ENFORCING) {
			error = EINVAL;
			break;
		}
		VLABEL_DPRINTF("syscall SETMODE: %d -> %d", vlabel_mode, val);
		SDT_PROBE2(vlabel, policy, mode, change, vlabel_mode, val);
		vlabel_mode = val;
		break;

	case VLABEL_SYS_GETSTATS:
		vlabel_rules_get_stats(&stats);
		error = copyout(&stats, arg, sizeof(stats));
		VLABEL_DPRINTF("syscall GETSTATS");
		break;

	case VLABEL_SYS_GETDEFPOL:
		error = copyout(&vlabel_default_policy, arg, sizeof(int));
		VLABEL_DPRINTF("syscall GETDEFPOL: %d", vlabel_default_policy);
		break;

	case VLABEL_SYS_SETDEFPOL:
		error = copyin(arg, &val, sizeof(int));
		if (error)
			break;
		VLABEL_DPRINTF("syscall SETDEFPOL: %d -> %d",
		    vlabel_default_policy, val);
		vlabel_default_policy = val;
		break;

	case VLABEL_SYS_RULE_ADD:
		/* Copyin the header */
		error = copyin(arg, &rule_arg, sizeof(rule_arg));
		if (error)
			break;

		/* Calculate and copyin variable data */
		data_len = rule_arg.vr_subject_len + rule_arg.vr_object_len +
		    rule_arg.vr_newlabel_len;
		if (data_len > VLABEL_MAX_LABEL_LEN * 3) {
			error = EINVAL;
			break;
		}

		data = malloc(data_len, M_TEMP, M_WAITOK);
		error = copyin((char *)arg + sizeof(rule_arg), data, data_len);
		if (error) {
			free(data, M_TEMP);
			break;
		}

		error = vlabel_rule_add_from_arg(&rule_arg, data);
		free(data, M_TEMP);
		VLABEL_DPRINTF("syscall RULE_ADD: action=%d ops=0x%x err=%d",
		    rule_arg.vr_action, rule_arg.vr_operations, error);
		break;

	case VLABEL_SYS_RULE_REMOVE:
		error = copyin(arg, &rule_id, sizeof(uint32_t));
		if (error)
			break;
		error = vlabel_rule_remove(rule_id);
		VLABEL_DPRINTF("syscall RULE_REMOVE: id=%u err=%d",
		    rule_id, error);
		break;

	case VLABEL_SYS_RULE_CLEAR:
		vlabel_rules_clear();
		error = 0;
		VLABEL_DPRINTF("syscall RULE_CLEAR");
		break;

	case VLABEL_SYS_RULE_LIST:
		error = copyin(arg, &list_arg, sizeof(list_arg));
		if (error)
			break;
		error = vlabel_rules_list(&list_arg);
		if (error == 0)
			error = copyout(&list_arg, arg, sizeof(list_arg));
		VLABEL_DPRINTF("syscall RULE_LIST: total=%u count=%u err=%d",
		    list_arg.vrl_total, list_arg.vrl_count, error);
		break;

	case VLABEL_SYS_TEST:
		error = copyin(arg, &test_arg, sizeof(test_arg));
		if (error)
			break;

		/* Copyin variable data */
		data_len = test_arg.vt_subject_len + test_arg.vt_object_len;
		if (data_len > VLABEL_MAX_LABEL_LEN * 2) {
			error = EINVAL;
			break;
		}

		data = malloc(data_len, M_TEMP, M_WAITOK);
		error = copyin((char *)arg + sizeof(test_arg), data, data_len);
		if (error) {
			free(data, M_TEMP);
			break;
		}

		error = vlabel_rules_test_access(
		    data, test_arg.vt_subject_len,
		    data + test_arg.vt_subject_len, test_arg.vt_object_len,
		    test_arg.vt_operation,
		    &test_arg.vt_result, &test_arg.vt_rule_id);
		free(data, M_TEMP);

		if (error == 0)
			error = copyout(&test_arg, arg, sizeof(test_arg));
		VLABEL_DPRINTF("syscall TEST: result=%u rule=%u err=%d",
		    test_arg.vt_result, test_arg.vt_rule_id, error);
		break;

	default:
		VLABEL_DPRINTF("syscall: unknown cmd %d", call);
		error = EINVAL;
		break;
	}

	return (error);
}

/*
 * Module registration
 *
 * We use no loadtime flags (0) because:
 * 1. We want to allow loading after boot for development/testing
 * 2. We do NOT allow unloading (no UNLOADOK flag) because MAC modules
 *    with UMA zones cannot safely unload - labels may still be attached
 *    to kernel objects (vnodes, creds) when mpo_destroy is called
 *
 * Flag behavior:
 *   - MPC_LOADTIME_FLAG_NOTLATE: Cannot load after boot
 *   - MPC_LOADTIME_FLAG_UNLOADOK: Can unload at runtime
 *   - 0 (no flags): Can load after boot, cannot unload
 *
 * This follows the pattern of MAC modules that allocate per-object labels.
 * To update the module during development, reboot the VM first.
 */
MAC_POLICY_SET(&vlabel_ops, mac_vlabel, "vLabel MAC Policy",
    0, &vlabel_slot);
