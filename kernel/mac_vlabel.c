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
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/extattr.h>
#include <sys/imgact.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * Global slot for storing our labels in MAC label structures
 */
int vlabel_slot;

/*
 * Configuration variables (exposed via sysctl)
 */
int vlabel_enabled = 1;
int vlabel_mode = VLABEL_MODE_PERMISSIVE;	/* Start permissive for safety */
int vlabel_audit_level = VLABEL_AUDIT_DENIALS;

/*
 * Default labels for unlabeled objects/subjects
 */
struct vlabel_label vlabel_default_object;
struct vlabel_label vlabel_default_subject;

/*
 * Statistics
 */
static struct vlabel_stats vlabel_stats;
static struct mtx vlabel_stats_mtx;

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

/*
 * Forward declarations for all entry points
 */

/* Policy lifecycle */
static void vlabel_destroy(struct mac_policy_conf *mpc);
static void vlabel_init(struct mac_policy_conf *mpc);
static int vlabel_syscall(struct thread *td, int call, void *arg);

/* Credential label lifecycle */
static void vlabel_cred_init_label(struct label *label);
static void vlabel_cred_destroy_label(struct label *label);
static void vlabel_cred_copy_label(struct label *src, struct label *dest);
static void vlabel_cred_relabel(struct ucred *cred, struct label *newlabel);
static int vlabel_cred_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed);
static int vlabel_cred_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed);

/* Credential checks */
static int vlabel_cred_check_relabel(struct ucred *cred, struct label *newlabel);
static int vlabel_cred_check_setuid(struct ucred *cred, uid_t uid);
static int vlabel_cred_check_setgid(struct ucred *cred, gid_t gid);
static int vlabel_cred_check_setgroups(struct ucred *cred, int ngroups,
    gid_t *gidset);

/* Process exec transition */
static void vlabel_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel);
static int vlabel_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel);

/* Vnode label lifecycle */
static void vlabel_vnode_init_label(struct label *label);
static void vlabel_vnode_destroy_label(struct label *label);
static void vlabel_vnode_copy_label(struct label *src, struct label *dest);
static int vlabel_vnode_associate_extattr(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel);
static int vlabel_vnode_create_extattr(struct ucred *cred, struct mount *mp,
    struct label *mplabel, struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel, struct componentname *cnp);
static int vlabel_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel);
static void vlabel_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel);
static int vlabel_vnode_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed);
static int vlabel_vnode_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed);

/* Vnode access checks */
static int vlabel_vnode_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode);
static int vlabel_vnode_check_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
static int vlabel_vnode_check_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
static int vlabel_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap);
static int vlabel_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type);
static int vlabel_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
static int vlabel_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel);
static int vlabel_vnode_check_getacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type);
static int vlabel_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
static int vlabel_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
static int vlabel_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace);
static int vlabel_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp);
static int vlabel_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot, int flags);
static int vlabel_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode);
static int vlabel_vnode_check_poll(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel);
static int vlabel_vnode_check_read(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel);
static int vlabel_vnode_check_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
static int vlabel_vnode_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
static int vlabel_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel);
static int vlabel_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
static int vlabel_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp);
static int vlabel_vnode_check_revoke(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
static int vlabel_vnode_check_setacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl);
static int vlabel_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
static int vlabel_vnode_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags);
static int vlabel_vnode_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode);
static int vlabel_vnode_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid);
static int vlabel_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime);
static int vlabel_vnode_check_stat(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel);
static int vlabel_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
static int vlabel_vnode_check_write(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel);

/* Mount label lifecycle */
static void vlabel_mount_init_label(struct label *label);
static void vlabel_mount_destroy_label(struct label *label);

/* Process checks */
static int vlabel_proc_check_debug(struct ucred *cred, struct proc *p);
static int vlabel_proc_check_sched(struct ucred *cred, struct proc *p);
static int vlabel_proc_check_signal(struct ucred *cred, struct proc *p,
    int signum);

/* Privilege grant */
static int vlabel_priv_grant(struct ucred *cred, int priv);

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

	/* Initialize statistics mutex */
	mtx_init(&vlabel_stats_mtx, "vlabel stats", NULL, MTX_DEF);

	/* Initialize default labels */
	memset(&vlabel_default_object, 0, sizeof(vlabel_default_object));
	strlcpy(vlabel_default_object.vl_type, "unlabeled",
	    sizeof(vlabel_default_object.vl_type));
	strlcpy(vlabel_default_object.vl_level, "default",
	    sizeof(vlabel_default_object.vl_level));
	vlabel_default_object.vl_flags = VLABEL_MATCH_TYPE | VLABEL_MATCH_LEVEL;

	memset(&vlabel_default_subject, 0, sizeof(vlabel_default_subject));
	strlcpy(vlabel_default_subject.vl_type, "user",
	    sizeof(vlabel_default_subject.vl_type));
	strlcpy(vlabel_default_subject.vl_level, "default",
	    sizeof(vlabel_default_subject.vl_level));
	vlabel_default_subject.vl_flags = VLABEL_MATCH_TYPE | VLABEL_MATCH_LEVEL;

	/* Clear statistics */
	memset(&vlabel_stats, 0, sizeof(vlabel_stats));

	VLABEL_DPRINTF("vLabel MAC policy initialized (mode=%d)", vlabel_mode);
}

static void
vlabel_destroy(struct mac_policy_conf *mpc)
{

	VLABEL_DPRINTF("destroying vLabel MAC policy");

	mtx_destroy(&vlabel_stats_mtx);

	VLABEL_DPRINTF("vLabel MAC policy destroyed");
}

static int
vlabel_syscall(struct thread *td, int call, void *arg)
{

	/* Reserved for future use */
	return (ENOSYS);
}

/*
 * Credential label lifecycle - STUBS
 *
 * These will be implemented in vlabel_label.c
 */

static void
vlabel_cred_init_label(struct label *label)
{

	/* TODO: Allocate and initialize credential label */
	SLOT_SET(label, NULL);
}

static void
vlabel_cred_destroy_label(struct label *label)
{

	/* TODO: Free credential label */
	SLOT_SET(label, NULL);
}

static void
vlabel_cred_copy_label(struct label *src, struct label *dest)
{

	/* TODO: Copy credential label */
}

static void
vlabel_cred_relabel(struct ucred *cred, struct label *newlabel)
{

	/* TODO: Relabel credential */
}

static int
vlabel_cred_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{

	/* TODO: Externalize credential label to string */
	return (0);
}

static int
vlabel_cred_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{

	/* TODO: Internalize credential label from string */
	return (0);
}

/*
 * Credential checks - STUBS (always allow)
 */

static int
vlabel_cred_check_relabel(struct ucred *cred, struct label *newlabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_cred_check_setuid(struct ucred *cred, uid_t uid)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_cred_check_setgid(struct ucred *cred, gid_t gid)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_cred_check_setgroups(struct ucred *cred, int ngroups, gid_t *gidset)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

/*
 * Process exec transition - STUBS
 */

static void
vlabel_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{

	/* TODO: Handle label transition on exec */
}

static int
vlabel_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{

	/* TODO: Check if exec will cause label transition */
	return (0);
}

/*
 * Vnode label lifecycle - STUBS
 */

static void
vlabel_vnode_init_label(struct label *label)
{

	/* TODO: Allocate vnode label */
	SLOT_SET(label, NULL);
}

static void
vlabel_vnode_destroy_label(struct label *label)
{

	/* TODO: Free vnode label */
	SLOT_SET(label, NULL);
}

static void
vlabel_vnode_copy_label(struct label *src, struct label *dest)
{

	/* TODO: Copy vnode label */
}

static int
vlabel_vnode_associate_extattr(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel)
{

	/*
	 * TODO: Read label from extended attribute
	 *
	 * This is called when a vnode is activated. We should read the
	 * system:vlabel extattr and parse it into our label structure.
	 */
	VLABEL_DPRINTF("associate_extattr called");
	return (0);
}

static int
vlabel_vnode_create_extattr(struct ucred *cred, struct mount *mp,
    struct label *mplabel, struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel, struct componentname *cnp)
{

	/* TODO: Set default label extattr on new file */
	return (0);
}

static int
vlabel_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel)
{

	/* TODO: Write label to extended attribute */
	return (0);
}

static void
vlabel_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{

	/* TODO: Update vnode label */
}

static int
vlabel_vnode_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{

	/* TODO: Externalize vnode label to string */
	return (0);
}

static int
vlabel_vnode_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{

	/* TODO: Internalize vnode label from string */
	return (0);
}

/*
 * Vnode access checks - STUBS (always allow)
 *
 * These are the main enforcement points. They will be implemented
 * to call vlabel_rules_check() once the rule engine is ready.
 */

static int
vlabel_vnode_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel)
{

	VLABEL_CHECK_ENABLED();

	/*
	 * TODO: This is the primary enforcement point for exec.
	 * Will call vlabel_rules_check(cred, subj, obj, VLABEL_OP_EXEC)
	 */
	VLABEL_DPRINTF("check_exec called");

	return (0);
}

static int
vlabel_vnode_check_getacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot, int flags)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_revoke(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_setacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

/*
 * Mount label lifecycle - STUBS
 */

static void
vlabel_mount_init_label(struct label *label)
{

	SLOT_SET(label, NULL);
}

static void
vlabel_mount_destroy_label(struct label *label)
{

	SLOT_SET(label, NULL);
}

/*
 * Process checks - STUBS (always allow)
 */

static int
vlabel_proc_check_debug(struct ucred *cred, struct proc *p)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_proc_check_sched(struct ucred *cred, struct proc *p)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

static int
vlabel_proc_check_signal(struct ucred *cred, struct proc *p, int signum)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

/*
 * Privilege grant - always deny (return EPERM)
 *
 * This prevents the policy from granting additional privileges.
 * We only restrict, never expand, access.
 */
static int
vlabel_priv_grant(struct ucred *cred, int priv)
{

	return (EPERM);
}

/*
 * Module registration
 */
MAC_POLICY_SET(&vlabel_ops, mac_vlabel, "vLabel MAC Policy",
    MPC_LOADTIME_FLAG_UNLOADOK, &vlabel_slot);
