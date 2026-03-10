/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel System-Level Access Checks
 *
 * Handles system-level operations: kld, reboot, sysctl, mount, etc.
 * These operations don't have traditional object labels - we check
 * against the subject's credential and a synthetic "system" label.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * Synthetic label for system objects (kld, reboot, sysctl, etc.)
 *
 * Since system operations don't have traditional object labels,
 * we use a synthetic label "type=system" to allow rules like:
 *   deny kld type=untrusted -> type=system
 *   allow kld type=admin -> type=system
 */
static struct vlabel_label vlabel_system_label;
static int vlabel_system_label_initialized = 0;

static void
vlabel_system_label_init(void)
{

	if (vlabel_system_label_initialized)
		return;

	/* Initialize as "type=system" */
	strlcpy(vlabel_system_label.vl_raw, "type=system",
	    sizeof(vlabel_system_label.vl_raw));
	vlabel_system_label.vl_npairs = 1;
	strlcpy(vlabel_system_label.vl_pairs[0].vp_key, "type",
	    sizeof(vlabel_system_label.vl_pairs[0].vp_key));
	strlcpy(vlabel_system_label.vl_pairs[0].vp_value, "system",
	    sizeof(vlabel_system_label.vl_pairs[0].vp_value));
	vlabel_system_label.vl_hash = vlabel_label_hash(
	    vlabel_system_label.vl_raw,
	    strlen(vlabel_system_label.vl_raw));

	vlabel_system_label_initialized = 1;
}

/*
 * kld_check_load - Check if credential can load a kernel module
 *
 * vp is the vnode of the module being loaded. If the module has a label,
 * we check against that; otherwise we use the system label.
 */
int
vlabel_kld_check_load(struct ucred *cred, struct vnode *vp,
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

	/* Use vnode label if available, otherwise system label */
	if (vplabel != NULL) {
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &vlabel_default_object;
	} else {
		vlabel_system_label_init();
		obj = &vlabel_system_label;
	}

	/* Check kld operation - maps to exec since we're loading code */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_EXEC, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * kld_check_stat - Check if credential can query loaded modules
 *
 * This is a subject-only check - no object involved.
 */
int
vlabel_kld_check_stat(struct ucred *cred)
{
	struct vlabel_label *subj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	vlabel_system_label_init();

	/* Check stat against system label */
	error = vlabel_rules_check(cred, subj, &vlabel_system_label,
	    VLABEL_OP_STAT, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_reboot - Check if credential can reboot the system
 */
int
vlabel_system_check_reboot(struct ucred *cred, int howto)
{
	struct vlabel_label *subj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	vlabel_system_label_init();

	/* Check write against system label - reboot modifies system state */
	error = vlabel_rules_check(cred, subj, &vlabel_system_label,
	    VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_sysctl - Check if credential can access sysctl
 *
 * This is called for every sysctl access. Be careful about performance.
 */
int
vlabel_system_check_sysctl(struct ucred *cred, struct sysctl_oid *oidp,
    void *arg1, int arg2, struct sysctl_req *req)
{
	struct vlabel_label *subj;
	uint32_t op;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	vlabel_system_label_init();

	/* Determine if read or write based on request */
	if (req != NULL && req->newptr != NULL)
		op = VLABEL_OP_WRITE;
	else
		op = VLABEL_OP_READ;

	error = vlabel_rules_check(cred, subj, &vlabel_system_label, op, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_acct - Check if credential can enable/disable accounting
 */
int
vlabel_system_check_acct(struct ucred *cred, struct vnode *vp,
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

	/* Use vnode label if provided, otherwise system label */
	if (vp != NULL && vplabel != NULL) {
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &vlabel_default_object;
	} else {
		vlabel_system_label_init();
		obj = &vlabel_system_label;
	}

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_swapon - Check if credential can enable swap
 */
int
vlabel_system_check_swapon(struct ucred *cred, struct vnode *vp,
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

	/* Use vnode label if provided, otherwise system label */
	if (vp != NULL && vplabel != NULL) {
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &vlabel_default_object;
	} else {
		vlabel_system_label_init();
		obj = &vlabel_system_label;
	}

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_swapoff - Check if credential can disable swap
 */
int
vlabel_system_check_swapoff(struct ucred *cred, struct vnode *vp,
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

	/* Use vnode label if provided, otherwise system label */
	if (vp != NULL && vplabel != NULL) {
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &vlabel_default_object;
	} else {
		vlabel_system_label_init();
		obj = &vlabel_system_label;
	}

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * mount_check_stat - Check if credential can stat a mount point
 */
int
vlabel_mount_check_stat(struct ucred *cred, struct mount *mp,
    struct label *mplabel)
{
	struct vlabel_label *subj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	vlabel_system_label_init();

	error = vlabel_rules_check(cred, subj, &vlabel_system_label,
	    VLABEL_OP_STAT, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * BSM Audit system checks
 *
 * These control access to BSM audit operations. The AUDIT operation
 * allows rules like:
 *   deny audit type=untrusted -> type=system
 */

/*
 * system_check_audit - Check if credential can submit an audit record
 */
int
vlabel_system_check_audit(struct ucred *cred, void *record, int length)
{
	struct vlabel_label *subj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	vlabel_system_label_init();

	error = vlabel_rules_check(cred, subj, &vlabel_system_label,
	    VLABEL_OP_AUDIT, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_auditctl - Check if credential can change audit log file
 */
int
vlabel_system_check_auditctl(struct ucred *cred, struct vnode *vp,
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

	/* Use vnode label if provided, otherwise system label */
	if (vp != NULL && vplabel != NULL) {
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &vlabel_default_object;
	} else {
		vlabel_system_label_init();
		obj = &vlabel_system_label;
	}

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_AUDIT, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_auditon - Check if credential can configure audit system
 */
int
vlabel_system_check_auditon(struct ucred *cred, int cmd)
{
	struct vlabel_label *subj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	vlabel_system_label_init();

	error = vlabel_rules_check(cred, subj, &vlabel_system_label,
	    VLABEL_OP_AUDIT, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}
