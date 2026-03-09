/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Credential Label Management
 *
 * Handles credential (process) label lifecycle and checks.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/imgact.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"
#include "vlabel_dtrace.h"

/*
 * Credential label lifecycle
 */

void
vlabel_cred_init_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(M_WAITOK);
	if (vl != NULL) {
		vlabel_label_set_default(vl, true);  /* true = subject label */
		/* DTrace: default subject label assigned */
		SDT_PROBE1(vlabel, label, extattr, default, 1);
	}
	SLOT_SET(label, vl);
}

void
vlabel_cred_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

void
vlabel_cred_copy_label(struct label *src, struct label *dest)
{
	struct vlabel_label *srcvl, *dstvl;

	if (src == NULL || dest == NULL)
		return;

	srcvl = SLOT(src);
	dstvl = SLOT(dest);

	if (srcvl != NULL && dstvl != NULL)
		vlabel_label_copy(srcvl, dstvl);
}

void
vlabel_cred_relabel(struct ucred *cred, struct label *newlabel)
{
	struct vlabel_label *vl, *newvl;

	vl = SLOT(cred->cr_label);
	newvl = SLOT(newlabel);

	if (vl != NULL && newvl != NULL)
		vlabel_label_copy(newvl, vl);
}

int
vlabel_cred_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct vlabel_label *vl;

	if (strcmp(element_name, "vlabel") != 0)
		return (0);

	vl = SLOT(label);
	if (vl == NULL)
		return (0);

	*claimed = 1;
	if (vl->vl_raw[0] != '\0')
		sbuf_cat(sb, vl->vl_raw);

	return (0);
}

int
vlabel_cred_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct vlabel_label *vl;
	int error;

	if (strcmp(element_name, "vlabel") != 0)
		return (0);

	vl = SLOT(label);
	if (vl == NULL)
		return (0);

	*claimed = 1;
	error = vlabel_label_parse(element_data, strlen(element_data), vl);

	return (error);
}

/*
 * Credential checks - STUBS (always allow)
 */

int
vlabel_cred_check_relabel(struct ucred *cred, struct label *newlabel)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_cred_check_setuid(struct ucred *cred, uid_t uid)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_cred_check_setgid(struct ucred *cred, gid_t gid)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_cred_check_setgroups(struct ucred *cred, int ngroups, gid_t *gidset)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

/*
 * Process exec transition
 *
 * When a process executes a binary that matches a TRANSITION rule,
 * the process adopts a new label specified by the rule. This is similar
 * to setuid but for MAC labels.
 */

void
vlabel_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vplabel,
    struct label *interpvplabel __unused,
    struct image_params *imgp __unused, struct label *execlabel __unused)
{
	struct vlabel_label *oldvl, *newvl, *objvl;
	struct vlabel_label *transition_label;
	int error;

	/* Don't do anything if not initialized yet */
	if (!vlabel_initialized)
		return;

	if (old == NULL || new == NULL || old->cr_label == NULL ||
	    new->cr_label == NULL)
		return;

	oldvl = SLOT(old->cr_label);
	newvl = SLOT(new->cr_label);

	if (oldvl == NULL || newvl == NULL)
		return;

	/* Get the object (executable) label */
	if (vplabel != NULL)
		objvl = SLOT(vplabel);
	else
		objvl = &vlabel_default_object;

	if (objvl == NULL)
		objvl = &vlabel_default_object;

	/*
	 * Allocate transition label dynamically - struct vlabel_label is ~9KB,
	 * too large for the kernel stack (typically 8-16KB).
	 */
	transition_label = malloc(sizeof(*transition_label), M_TEMP, M_WAITOK | M_ZERO);

	/*
	 * Check if a transition rule matches and get the new label.
	 * If no transition rule matches, the label was already copied
	 * by cred_copy_label and we keep the inherited label.
	 */
	error = vlabel_rules_get_transition(old, oldvl, objvl, transition_label);
	if (error == 0) {
		/* Apply the transition - copy new label to credential */
		vlabel_label_copy(transition_label, newvl);
		/* DTrace: transition occurred */
		SDT_PROBE4(vlabel, cred, transition, exec,
		    oldvl->vl_raw, newvl->vl_raw, objvl->vl_raw,
		    curproc ? curproc->p_pid : 0);
		VLABEL_DPRINTF("execve_transition: '%s' -> '%s' via exec of '%s'",
		    oldvl->vl_raw, newvl->vl_raw,
		    objvl->vl_raw[0] ? objvl->vl_raw : "(unlabeled)");
	} else {
		VLABEL_DPRINTF("execve_transition: no transition, "
		    "subject '%s' exec object '%s'",
		    oldvl->vl_raw,
		    objvl->vl_raw[0] ? objvl->vl_raw : "(unlabeled)");
	}

	free(transition_label, M_TEMP);
}

int
vlabel_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel __unused,
    struct image_params *imgp __unused, struct label *execlabel __unused)
{
	struct vlabel_label *subjvl, *objvl;

	/*
	 * Return non-zero if exec will cause a label transition.
	 * The MAC framework uses this to decide whether to allocate
	 * a new credential for the process.
	 */

	/* Not ready yet during early boot */
	if (!vlabel_initialized)
		return (0);

	if (old == NULL || old->cr_label == NULL)
		return (0);

	subjvl = SLOT(old->cr_label);
	if (subjvl == NULL)
		return (0);

	/* Get the object (executable) label */
	if (vplabel != NULL)
		objvl = SLOT(vplabel);
	else
		objvl = &vlabel_default_object;

	if (objvl == NULL)
		objvl = &vlabel_default_object;

	return (vlabel_rules_will_transition(old, subjvl, objvl) ? 1 : 0);
}
