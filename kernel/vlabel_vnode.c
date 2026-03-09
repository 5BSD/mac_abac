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
	VLABEL_DPRINTF("vnode_init_label: allocated label %p", vl);
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
		VLABEL_DPRINTF("read_extattr: NULL label slot");
		return;
	}

	/*
	 * Allocate buffer on heap - VLABEL_MAX_LABEL_LEN (12KB) is too
	 * large for the kernel stack (typically 4-8KB).
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

	VLABEL_DPRINTF("read_extattr: vn_extattr_get returned %d, buflen=%d",
	    error, buflen);

	if (error == ENOATTR || error == EOPNOTSUPP) {
		/*
		 * No label on this vnode - use default object label.
		 */
		free(buf, M_TEMP);
		vlabel_label_set_default(vl, false);
		/* DTrace: default label assigned */
		SDT_PROBE1(vlabel, label, extattr, default, 0);
		atomic_add_64(&vlabel_labels_default, 1);
		VLABEL_DPRINTF("read_extattr: no label (err=%d), using default",
		    error);
		return;
	} else if (error != 0) {
		/*
		 * Error reading extattr - use default and log.
		 */
		VLABEL_DPRINTF("read_extattr: error %d reading extattr",
		    error);
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
		VLABEL_DPRINTF("read_extattr: parse error %d for '%s'",
		    error, buf);
		free(buf, M_TEMP);
		vlabel_label_set_default(vl, false);
		return;
	}

	free(buf, M_TEMP);
	/* DTrace: label read from extattr */
	SDT_PROBE2(vlabel, label, extattr, read, vl->vl_raw, vp);
	atomic_add_64(&vlabel_labels_read, 1);

	VLABEL_DPRINTF("read_extattr: loaded label '%s'", vl->vl_raw);
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

int
vlabel_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel)
{
	struct vlabel_label *vl, *newvl;

	/*
	 * Update the in-memory vnode label from intlabel.
	 * The extattr has already been written by the caller.
	 */
	if (vplabel == NULL || intlabel == NULL)
		return (0);

	vl = SLOT(vplabel);
	newvl = SLOT(intlabel);

	if (vl != NULL && newvl != NULL) {
		vlabel_label_copy(newvl, vl);
		VLABEL_DPRINTF("setlabel_extattr: updated label to '%s'",
		    vl->vl_raw);
	}

	return (0);
}

void
vlabel_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{

	/*
	 * Stub: Label updates are handled via extattr and setlabel_extattr.
	 * This callback is currently a no-op.
	 */
}

int
vlabel_vnode_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{

	/*
	 * Stub: Label externalization (for mac_get_file) not implemented.
	 * Use vlabelctl label get or getextattr to read labels.
	 */
	return (0);
}

int
vlabel_vnode_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{

	/*
	 * Stub: Label internalization (for mac_set_file) not implemented.
	 * Use vlabelctl label set or setextattr to write labels.
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

	VLABEL_CHECK_ENABLED();
	/* STUB: Always allows - see note above */
	return (0);
}

int
vlabel_vnode_check_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{

	VLABEL_CHECK_ENABLED();
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
		VLABEL_DPRINTF("check_exec: no credential label");
		return (0);
	}
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL) {
		VLABEL_DPRINTF("check_exec: no vnode label");
		return (0);
	}
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	VLABEL_DPRINTF("check_exec: subj='%s' obj='%s'",
	    subj->vl_raw, obj->vl_raw);

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_EXEC);

	/*
	 * In permissive mode, log but don't enforce.
	 */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE) {
		VLABEL_DPRINTF("check_exec: DENIED (permissive mode, allowing)");
		return (0);
	}

	if (error != 0) {
		VLABEL_DPRINTF("check_exec: DENIED");
	}

	return (error);
}

int
vlabel_vnode_check_getacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot, int flags)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_revoke(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_setacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
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
