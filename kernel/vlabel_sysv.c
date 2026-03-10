/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel SysV IPC Label Management
 *
 * Handles SysV IPC (message queues, semaphores, shared memory)
 * label lifecycle and access checks.
 * IPC object labels are inherited from the creating credential.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/ucred.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * ============================================================
 * SysV Message Queue Labels
 * ============================================================
 */

void
vlabel_sysvmsg_init_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
vlabel_sysvmsg_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

void
vlabel_sysvmsg_cleanup(struct label *msglabel)
{
	struct vlabel_label *vl;

	vl = SLOT(msglabel);
	if (vl != NULL)
		memset(vl, 0, sizeof(*vl));
}

void
vlabel_sysvmsg_create(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqlabel, struct msg *msgptr, struct label *msglabel)
{
	struct vlabel_label *credlabel, *mlabel;

	if (cred == NULL || cred->cr_label == NULL || msglabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	mlabel = SLOT(msglabel);

	if (credlabel != NULL && mlabel != NULL)
		vlabel_label_copy(credlabel, mlabel);
}

/*
 * ============================================================
 * SysV Message Queue (msq) Labels and Checks
 * ============================================================
 */

void
vlabel_sysvmsq_init_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
vlabel_sysvmsq_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

void
vlabel_sysvmsq_cleanup(struct label *msqlabel)
{
	struct vlabel_label *vl;

	vl = SLOT(msqlabel);
	if (vl != NULL)
		memset(vl, 0, sizeof(*vl));
}

void
vlabel_sysvmsq_create(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqlabel)
{
	struct vlabel_label *credlabel, *mlabel;

	if (cred == NULL || cred->cr_label == NULL || msqlabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	mlabel = SLOT(msqlabel);

	if (credlabel != NULL && mlabel != NULL)
		vlabel_label_copy(credlabel, mlabel);
}

int
vlabel_sysvmsq_check_msgmsq(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (msqklabel == NULL)
		return (0);
	obj = SLOT(msqklabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvmsq_check_msgrcv(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (msglabel == NULL)
		return (0);
	obj = SLOT(msglabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_READ, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvmsq_check_msgrmid(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (msglabel == NULL)
		return (0);
	obj = SLOT(msglabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_UNLINK, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvmsq_check_msqget(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (msqklabel == NULL)
		return (0);
	obj = SLOT(msqklabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_OPEN, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvmsq_check_msqctl(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel, int cmd)
{
	struct vlabel_label *subj, *obj;
	int error;
	uint32_t op;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (msqklabel == NULL)
		return (0);
	obj = SLOT(msqklabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* IPC_STAT is read, IPC_SET/IPC_RMID are write */
	op = (cmd == IPC_STAT) ? VLABEL_OP_STAT : VLABEL_OP_WRITE;
	error = vlabel_rules_check(cred, subj, obj, op, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvmsq_check_msqrcv(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (msqklabel == NULL)
		return (0);
	obj = SLOT(msqklabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_READ, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvmsq_check_msqsnd(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (msqklabel == NULL)
		return (0);
	obj = SLOT(msqklabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * ============================================================
 * SysV Semaphore Labels and Checks
 * ============================================================
 */

void
vlabel_sysvsem_init_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
vlabel_sysvsem_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

void
vlabel_sysvsem_cleanup(struct label *semalabel)
{
	struct vlabel_label *vl;

	vl = SLOT(semalabel);
	if (vl != NULL)
		memset(vl, 0, sizeof(*vl));
}

void
vlabel_sysvsem_create(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semalabel)
{
	struct vlabel_label *credlabel, *slabel;

	if (cred == NULL || cred->cr_label == NULL || semalabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	slabel = SLOT(semalabel);

	if (credlabel != NULL && slabel != NULL)
		vlabel_label_copy(credlabel, slabel);
}

int
vlabel_sysvsem_check_semctl(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel, int cmd)
{
	struct vlabel_label *subj, *obj;
	int error;
	uint32_t op;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (semaklabel == NULL)
		return (0);
	obj = SLOT(semaklabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* IPC_STAT/GETVAL/etc are read, IPC_SET/IPC_RMID/SETVAL are write */
	switch (cmd) {
	case IPC_STAT:
	case GETVAL:
	case GETPID:
	case GETNCNT:
	case GETZCNT:
	case GETALL:
		op = VLABEL_OP_STAT;
		break;
	default:
		op = VLABEL_OP_WRITE;
		break;
	}

	error = vlabel_rules_check(cred, subj, obj, op, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvsem_check_semget(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (semaklabel == NULL)
		return (0);
	obj = SLOT(semaklabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_OPEN, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvsem_check_semop(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel, size_t accesstype)
{
	struct vlabel_label *subj, *obj;
	int error;
	uint32_t op;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (semaklabel == NULL)
		return (0);
	obj = SLOT(semaklabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* accesstype: SEM_R for read, SEM_A for alter */
	op = (accesstype & SEM_A) ? VLABEL_OP_WRITE : VLABEL_OP_READ;
	error = vlabel_rules_check(cred, subj, obj, op, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * ============================================================
 * SysV Shared Memory Labels and Checks
 * ============================================================
 */

void
vlabel_sysvshm_init_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
vlabel_sysvshm_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

void
vlabel_sysvshm_cleanup(struct label *shmlabel)
{
	struct vlabel_label *vl;

	vl = SLOT(shmlabel);
	if (vl != NULL)
		memset(vl, 0, sizeof(*vl));
}

void
vlabel_sysvshm_create(struct ucred *cred, struct shmid_kernel *shmsegptr,
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

int
vlabel_sysvshm_check_shmat(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int shmflg)
{
	struct vlabel_label *subj, *obj;
	int error;
	uint32_t op;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmseglabel == NULL)
		return (0);
	obj = SLOT(shmseglabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* SHM_RDONLY means read, otherwise read+write */
	op = (shmflg & SHM_RDONLY) ? VLABEL_OP_READ : (VLABEL_OP_READ | VLABEL_OP_WRITE);
	error = vlabel_rules_check(cred, subj, obj, op, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvshm_check_shmctl(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int cmd)
{
	struct vlabel_label *subj, *obj;
	int error;
	uint32_t op;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmseglabel == NULL)
		return (0);
	obj = SLOT(shmseglabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* IPC_STAT is read, IPC_SET/IPC_RMID are write */
	op = (cmd == IPC_STAT) ? VLABEL_OP_STAT : VLABEL_OP_WRITE;
	error = vlabel_rules_check(cred, subj, obj, op, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvshm_check_shmdt(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmseglabel == NULL)
		return (0);
	obj = SLOT(shmseglabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Detach is always allowed if you have any access */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_READ, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_sysvshm_check_shmget(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int shmflg)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (shmseglabel == NULL)
		return (0);
	obj = SLOT(shmseglabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_OPEN, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}
