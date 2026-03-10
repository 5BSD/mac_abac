/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel POSIX Shared Memory Label Management
 *
 * Handles POSIX shm label lifecycle and access checks.
 * Shared memory labels are inherited from the creating credential.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * POSIX shm label lifecycle
 */

void
vlabel_posixshm_init_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
vlabel_posixshm_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

/*
 * POSIX shm creation - inherit label from creating credential
 */
void
vlabel_posixshm_create(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel)
{
	struct vlabel_label *credlabel, *slabel;

	if (cred == NULL || cred->cr_label == NULL || shmlabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	slabel = SLOT(shmlabel);

	if (credlabel != NULL && slabel != NULL)
		vlabel_label_copy(credlabel, slabel);
}

/*
 * POSIX shm access checks
 */

int
vlabel_posixshm_check_create(struct ucred *cred, const char *path)
{

	/* Creation is always allowed - the shm inherits creator's label */
	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_posixshm_check_mmap(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, int prot, int flags)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmlabel == NULL)
		return (0);
	obj = SLOT(shmlabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_MMAP, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixshm_check_open(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, accmode_t accmode)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmlabel == NULL)
		return (0);
	obj = SLOT(shmlabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_OPEN, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixshm_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct shmfd *shmfd, struct label *shmlabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmlabel == NULL)
		return (0);
	obj = SLOT(shmlabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_READ, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixshm_check_setmode(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, mode_t mode)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmlabel == NULL)
		return (0);
	obj = SLOT(shmlabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use WRITE as proxy for setmode - modifying metadata */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixshm_check_setowner(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, uid_t uid, gid_t gid)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmlabel == NULL)
		return (0);
	obj = SLOT(shmlabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Use WRITE as proxy for setowner - modifying metadata */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixshm_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct shmfd *shmfd, struct label *shmlabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmlabel == NULL)
		return (0);
	obj = SLOT(shmlabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_STAT, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixshm_check_truncate(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmlabel == NULL)
		return (0);
	obj = SLOT(shmlabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixshm_check_unlink(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmlabel == NULL)
		return (0);
	obj = SLOT(shmlabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_UNLINK, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_posixshm_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct shmfd *shmfd, struct label *shmlabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmlabel == NULL)
		return (0);
	obj = SLOT(shmlabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(active_cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}
