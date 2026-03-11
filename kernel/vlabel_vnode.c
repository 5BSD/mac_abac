/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Vnode Label Management
 *
 * Handles vnode label lifecycle, extattr integration, and access checks.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/sbuf.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/extattr.h>
#include <sys/imgact.h>
#include <sys/acl.h>

#include <machine/atomic.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"
#include "vlabel_dtrace.h"

/*
 * Statistics - defined in mac_vlabel.c, updated here
 */
extern uint64_t vlabel_labels_read;
extern uint64_t vlabel_labels_default;

/*
 * Configurable extended attribute name - defined in mac_vlabel.c
 */
extern char vlabel_extattr_name[64];

/*
 * Vnode label lifecycle
 */

void
vlabel_vnode_init_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
vlabel_vnode_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

void
vlabel_vnode_copy_label(struct label *src, struct label *dest)
{
	struct vlabel_label *srcvl, *dstvl;

	/* NULL check label pointers before accessing slots */
	if (src == NULL || dest == NULL)
		return;

	srcvl = SLOT(src);
	dstvl = SLOT(dest);

	if (srcvl != NULL && dstvl != NULL)
		vlabel_label_copy(srcvl, dstvl);
}

/*
 * Helper function to read label from extended attribute.
 * Used by both associate_extattr (UFS multilabel) and
 * associate_singlelabel (ZFS and other filesystems).
 */
static void
vlabel_vnode_read_extattr(struct vnode *vp, struct label *vplabel)
{
	struct vlabel_label *vl;
	char *buf;
	int buflen, error;

	vl = SLOT(vplabel);
	if (vl == NULL) {
		return;
	}

	/*
	 * Allocate buffer on heap - VLABEL_MAX_LABEL_LEN (4KB) is allocated
	 * on the heap for consistency with other label operations and to
	 * reduce kernel stack pressure.
	 *
	 * M_WAITOK guarantees success (kernel will sleep until memory
	 * is available, or panic if impossible).
	 */
	buf = malloc(VLABEL_MAX_LABEL_LEN, M_TEMP, M_WAITOK | M_ZERO);

	/*
	 * Read the label from the system:vlabel extended attribute.
	 */
	buflen = VLABEL_MAX_LABEL_LEN - 1;

	error = vn_extattr_get(vp, IO_NODELOCKED, VLABEL_EXTATTR_NAMESPACE,
	    vlabel_extattr_name, &buflen, buf, curthread);

	if (error == ENOATTR || error == EOPNOTSUPP) {
		/*
		 * No label on this vnode - use default object label.
		 */
		free(buf, M_TEMP);
		vlabel_label_set_default(vl, false);
		/* DTrace: default label assigned */
		SDT_PROBE1(vlabel, label, extattr, default, 0);
		atomic_add_64(&vlabel_labels_default, 1);
		return;
	} else if (error != 0) {
		/*
		 * Error reading extattr - use default.
		 */
		free(buf, M_TEMP);
		vlabel_label_set_default(vl, false);
		return;
	}

	/*
	 * Parse the label string.
	 */
	buf[buflen] = '\0';
	error = vlabel_label_parse(buf, buflen, vl);
	if (error != 0) {
		free(buf, M_TEMP);
		vlabel_label_set_default(vl, false);
		return;
	}

	free(buf, M_TEMP);
	/* DTrace: label read from extattr */
	SDT_PROBE2(vlabel, label, extattr, read, vl->vl_raw, vp);
	atomic_add_64(&vlabel_labels_read, 1);

}

/*
 * Refresh vnode label by re-reading from extended attribute.
 * Called via VLABEL_SYS_REFRESH syscall for live relabeling.
 */
void
vlabel_vnode_refresh_label(struct vnode *vp, struct label *vplabel)
{

	vlabel_vnode_read_extattr(vp, vplabel);
}

/*
 * Associate vnode label from extended attribute (UFS with multilabel).
 */
int
vlabel_vnode_associate_extattr(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel)
{

	vlabel_vnode_read_extattr(vp, vplabel);
	return (0);
}

/*
 * Associate vnode label for single-label filesystems (ZFS, tmpfs, etc).
 *
 * Even though these filesystems don't set MNT_MULTILABEL, they may still
 * support extended attributes. We attempt to read per-file labels from
 * extattr, falling back to the default label if not present.
 */
void
vlabel_vnode_associate_singlelabel(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel)
{

	vlabel_vnode_read_extattr(vp, vplabel);
}

int
vlabel_vnode_create_extattr(struct ucred *cred, struct mount *mp,
    struct label *mplabel, struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel, struct componentname *cnp)
{

	/*
	 * Stub: New files get the default object label assigned in
	 * vlabel_vnode_init_label(). Setting extattr automatically on
	 * file creation is not implemented - use vlabelctl label set.
	 */
	return (0);
}


/*
 * Vnode access checks
 *
 * NOTE: Currently only check_exec is fully implemented with rule evaluation.
 * All other vnode check hooks are stubs that always return 0 (allow).
 * This is intentional for the initial implementation - enforcement of
 * read/write/mmap/etc operations would require careful analysis of the
 * performance impact and proper rule configuration by administrators.
 *
 * To enable enforcement for additional operations:
 * 1. Copy the pattern from vlabel_vnode_check_exec()
 * 2. Use the appropriate VLABEL_OP_* constant
 * 3. Test thoroughly with realistic workloads
 */

int
vlabel_vnode_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_ACCESS, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_CHDIR, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use CHDIR for chroot - both are directory access checks */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_CHDIR, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Check against parent directory label */
	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_CREATE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use WRITE as proxy for ACL modification */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/*
	 * Always protect our own label attribute from deletion.
	 * This prevents unauthorized removal of security labels.
	 */
	if (attrnamespace == VLABEL_EXTATTR_NAMESPACE &&
	    name != NULL && strcmp(name, vlabel_extattr_name) == 0) {
		/* Get subject label from credential */
		if (cred == NULL || cred->cr_label == NULL)
			return (EPERM);
		subj = SLOT(cred->cr_label);
		if (subj == NULL)
			subj = &vlabel_default_subject;

		/* Get object label from vnode */
		if (vplabel == NULL)
			return (EPERM);
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &vlabel_default_object;

		/* Check setextattr operation - deletion is a form of modification */
		error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_SETEXTATTR, NULL);

		/* In permissive mode, log but allow */
		if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
			return (0);

		return (error);
	}

	return (0);
}

int
vlabel_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL) {
		return (0);
	}
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL) {
		return (0);
	}
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules - no target process for vnode ops */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_EXEC, NULL);

	/* In permissive mode, don't enforce */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_getacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use STAT as proxy for reading ACLs */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_STAT, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/*
	 * Optionally protect reading of our label attribute.
	 * This can prevent information disclosure about security labels.
	 *
	 * Only check for our specific attribute - don't block other extattrs.
	 */
	if (attrnamespace == VLABEL_EXTATTR_NAMESPACE &&
	    name != NULL && strcmp(name, vlabel_extattr_name) == 0) {
		/* Get subject label from credential */
		if (cred == NULL || cred->cr_label == NULL)
			return (0);  /* Allow if no cred - kernel internal */
		subj = SLOT(cred->cr_label);
		if (subj == NULL)
			subj = &vlabel_default_subject;

		/* Get object label from vnode */
		if (vplabel == NULL)
			return (0);
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &vlabel_default_object;

		/* Check getextattr operation */
		error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_GETEXTATTR, NULL);

		/* In permissive mode, log but allow */
		if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
			return (0);

		return (error);
	}

	return (0);
}

int
vlabel_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Check against target file's label */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_LINK, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use GETEXTATTR as proxy for listing extattrs */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_GETEXTATTR, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_LOOKUP, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot, int flags)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_MMAP, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * vlabel_vnode_check_mprotect - Check mprotect() protection changes
 *
 * Called when a process attempts to change the protection of a memory
 * mapping that is backed by a vnode. This is useful for W^X enforcement:
 * preventing the same memory from being both writable and executable.
 *
 * The 'prot' parameter contains the new protection flags (PROT_READ,
 * PROT_WRITE, PROT_EXEC).
 *
 * Use cases:
 *   - Prevent untrusted processes from making memory executable
 *   - Enforce W^X policy on file-backed mappings
 */
int
vlabel_vnode_check_mprotect(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_MPROTECT, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_OPEN, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use READ as proxy for poll - checking readability */
	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_READ, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_READ, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_READDIR, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules - use READ since readlink is reading symlink target */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_READ, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use SETEXTATTR as proxy for relabeling */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_SETEXTATTR, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Check against source file's label */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_RENAME, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Check against target directory's label */
	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_RENAME, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_revoke(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use WRITE as proxy for revoke - modifies file state */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_setacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use WRITE as proxy for ACL modification */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/*
	 * Always protect our own label attribute from modification.
	 * This prevents unauthorized changes to security labels.
	 *
	 * Note: vlabelctl uses this path to set labels, so rules must
	 * allow setextattr for administrative processes. Example:
	 *   allow setextattr type=admin -> *
	 *   deny setextattr * -> *
	 */
	if (attrnamespace == VLABEL_EXTATTR_NAMESPACE &&
	    name != NULL && strcmp(name, vlabel_extattr_name) == 0) {
		/* Get subject label from credential */
		if (cred == NULL || cred->cr_label == NULL)
			return (EPERM);
		subj = SLOT(cred->cr_label);
		if (subj == NULL)
			subj = &vlabel_default_subject;

		/* Get object label from vnode */
		if (vplabel == NULL)
			return (EPERM);
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &vlabel_default_object;

		/* Check setextattr operation */
		error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_SETEXTATTR, NULL);

		/* In permissive mode, log but allow */
		if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
			return (0);

		return (error);
	}

	return (0);
}

int
vlabel_vnode_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use WRITE as proxy for setting file flags */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use WRITE as proxy for chmod */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use WRITE as proxy for chown */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use WRITE as proxy for utimes */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_STAT, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Check against target file's label */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_UNLINK, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_WRITE, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * Check mmap protection downgrade (W^X enforcement).
 *
 * This hook is called when mmap() protections might be downgraded
 * (e.g., from RWX to RX or RW). This is the companion to mprotect()
 * for W^X enforcement.
 *
 * Unlike check_mprotect which returns an error, this hook modifies
 * the protection bits directly by clearing disallowed combinations.
 *
 * For example, to enforce W^X on untrusted code:
 *   - If PROT_WRITE and PROT_EXEC are both set, clear PROT_EXEC
 *
 * Currently we don't modify protections - this is a stub for future
 * W^X policy implementation. To enable, rules would look like:
 *   deny mmap type=untrusted -> *   (with PROT_WRITE|PROT_EXEC check)
 */
void
vlabel_vnode_check_mmap_downgrade(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int *prot)
{
	/*
	 * Stub implementation - does not modify protections.
	 *
	 * A full W^X implementation would:
	 * 1. Get subject/object labels
	 * 2. Check if policy requires W^X for this combination
	 * 3. If (*prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)
	 *    then *prot &= ~PROT_EXEC;
	 */
	(void)cred;
	(void)vp;
	(void)vplabel;
	(void)prot;
}

/*
 * Set vnode label in extended attribute.
 *
 * This hook is called when a label needs to be written to persistent
 * storage (extended attribute). It's typically invoked after
 * vnode_check_relabel approves the label change.
 *
 * The intlabel parameter contains the new label to write.
 *
 * Returns 0 on success, error code on failure.
 */
int
vlabel_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel)
{
	struct vlabel_label *newlabel;
	char *buf;
	int error, len;

	VLABEL_CHECK_ENABLED();

	if (intlabel == NULL)
		return (EINVAL);

	newlabel = SLOT(intlabel);
	if (newlabel == NULL)
		return (EINVAL);

	/*
	 * Allocate buffer on heap for consistency with other label
	 * operations and to reduce kernel stack pressure.
	 */
	buf = malloc(VLABEL_MAX_LABEL_LEN, M_TEMP, M_WAITOK);

	/* Serialize label to string format */
	len = vlabel_label_to_string(newlabel, buf, VLABEL_MAX_LABEL_LEN);
	if (len < 0) {
		free(buf, M_TEMP);
		return (EINVAL);
	}

	/* Write to extended attribute */
	error = vn_extattr_set(vp, UIO_SYSSPACE, VLABEL_EXTATTR_NAMESPACE,
	    vlabel_extattr_name, len, buf, curthread);

	free(buf, M_TEMP);

	if (error == 0 && vplabel != NULL) {
		/* Update in-memory label */
		struct vlabel_label *vl = SLOT(vplabel);
		if (vl != NULL)
			vlabel_label_copy(newlabel, vl);
	}

	return (error);
}

/*
 * Mount label lifecycle
 */

void
vlabel_mount_init_label(struct label *label)
{

	SLOT_SET(label, NULL);
}

void
vlabel_mount_destroy_label(struct label *label)
{

	SLOT_SET(label, NULL);
}
