/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel POSIX Semaphore Label Management
 *
 * Handles POSIX semaphore label lifecycle and access checks.
 * Semaphore labels are inherited from the creating credential.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/ucred.h>
#include <sys/ksem.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * POSIX semaphore label lifecycle
 */

void
vlabel_posixsem_init_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
vlabel_posixsem_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

/*
 * POSIX semaphore creation - inherit label from creating credential
 */
void
vlabel_posixsem_create(struct ucred *cred, struct ksem *ks,
    struct label *kslabel)
{
	struct vlabel_label *credlabel, *slabel;

	if (cred == NULL || cred->cr_label == NULL || kslabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	slabel = SLOT(kslabel);

	if (credlabel != NULL && slabel != NULL)
		vlabel_label_copy(credlabel, slabel);
}

/*
 * POSIX semaphore access checks
 */

int
vlabel_posixsem_check_getvalue(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_READ, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixsem_check_open(struct ucred *cred, struct ksem *ks,
    struct label *kslabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_OPEN, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixsem_check_post(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* post = increment = write operation */
	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixsem_check_setmode(struct ucred *cred, struct ksem *ks,
    struct label *kslabel, mode_t mode)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixsem_check_setowner(struct ucred *cred, struct ksem *ks,
    struct label *kslabel, uid_t uid, gid_t gid)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixsem_check_stat(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_STAT, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixsem_check_unlink(struct ucred *cred, struct ksem *ks,
    struct label *kslabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_UNLINK, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixsem_check_wait(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* wait = decrement = read operation (blocking read) */
	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_READ, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}
