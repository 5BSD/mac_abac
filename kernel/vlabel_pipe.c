/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Pipe Label Management
 *
 * Handles pipe label lifecycle and access checks.
 * Pipe labels are inherited from the creating credential.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/selinfo.h>
#include <sys/pipe.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * Pipe label lifecycle
 */

void
vlabel_pipe_init_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
	VLABEL_DPRINTF("pipe_init_label: allocated label %p", vl);
}

void
vlabel_pipe_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

void
vlabel_pipe_copy_label(struct label *src, struct label *dest)
{
	struct vlabel_label *srcvl, *dstvl;

	if (src == NULL || dest == NULL)
		return;

	srcvl = SLOT(src);
	dstvl = SLOT(dest);

	if (srcvl != NULL && dstvl != NULL)
		vlabel_label_copy(srcvl, dstvl);
}

/*
 * Pipe creation - inherit label from creating credential
 */
void
vlabel_pipe_create(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct vlabel_label *credlabel, *plabel;

	if (cred == NULL || cred->cr_label == NULL || pplabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	plabel = SLOT(pplabel);

	if (credlabel != NULL && plabel != NULL) {
		vlabel_label_copy(credlabel, plabel);
		VLABEL_DPRINTF("pipe_create: inherited label '%s' from cred",
		    plabel->vl_raw);
	}
}

/*
 * Pipe access checks
 *
 * For pipe operations, the subject is the process credential and
 * the object is the pipe label. This allows rules like:
 *   deny read type=untrusted -> type=secret
 *   deny write type=sandbox -> *
 */

int
vlabel_pipe_check_ioctl(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, unsigned long cmd, void *data)
{

	/* ioctl on pipes is always allowed - typically FIONREAD etc. */
	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_pipe_check_poll(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{

	/* poll is always allowed - no security impact */
	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_pipe_check_read(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
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

	/* Get object label from pipe */
	if (pplabel == NULL)
		return (0);
	obj = SLOT(pplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_READ, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_pipe_check_relabel(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, struct label *newlabel)
{

	/* Pipe relabeling not supported in vLabel */
	VLABEL_CHECK_ENABLED();
	return (EACCES);
}

int
vlabel_pipe_check_stat(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
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

	/* Get object label from pipe */
	if (pplabel == NULL)
		return (0);
	obj = SLOT(pplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_STAT, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_pipe_check_write(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
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

	/* Get object label from pipe */
	if (pplabel == NULL)
		return (0);
	obj = SLOT(pplabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}
