/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Process Checks
 *
 * Handles process-related access checks and privilege grants.
 * These checks control inter-process operations like debugging,
 * signaling, and scheduler manipulation.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * vlabel_proc_check_debug - Check if subject can debug target process
 *
 * This controls ptrace(), procfs access, and other debugging operations.
 * The subject is the debugger, the object is the process being debugged.
 *
 * Context constraints are checked against the SUBJECT (debugger) credential,
 * allowing rules like "deny debug if debugger is sandboxed" or
 * "deny debug from within jails".
 */
int
vlabel_proc_check_debug(struct ucred *cred, struct proc *p)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject (debugger) label from credential */
	if (cred == NULL || cred->cr_label == NULL) {
		return (0);
	}
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object (target process) label from its credential */
	if (p == NULL || p->p_ucred == NULL || p->p_ucred->cr_label == NULL) {
		return (0);
	}
	obj = SLOT(p->p_ucred->cr_label);
	if (obj == NULL)
		obj = &vlabel_default_subject;  /* Processes use subject default */

	/* Evaluate rules - pass target process for object context checks */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_DEBUG, p);

	/* In permissive mode, don't enforce */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * vlabel_proc_check_sched - Check if subject can affect target's scheduling
 *
 * Controls setpriority(), sched_setscheduler(), etc.
 */
int
vlabel_proc_check_sched(struct ucred *cred, struct proc *p)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object (target process) label */
	if (p == NULL || p->p_ucred == NULL || p->p_ucred->cr_label == NULL)
		return (0);
	obj = SLOT(p->p_ucred->cr_label);
	if (obj == NULL)
		obj = &vlabel_default_subject;

	/* Evaluate rules - pass target process for object context checks */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_SCHED, p);

	/* Permissive mode handling */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * vlabel_proc_check_signal - Check if subject can send signal to target
 *
 * Controls kill(), sigqueue(), etc.
 */
int
vlabel_proc_check_signal(struct ucred *cred, struct proc *p, int signum)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object (target process) label */
	if (p == NULL || p->p_ucred == NULL || p->p_ucred->cr_label == NULL)
		return (0);
	obj = SLOT(p->p_ucred->cr_label);
	if (obj == NULL)
		obj = &vlabel_default_subject;

	/* Evaluate rules - pass target process for object context checks */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_SIGNAL, p);

	/* Permissive mode handling */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * Privilege grant - always deny (return EPERM)
 *
 * This prevents the policy from granting additional privileges.
 * We only restrict, never expand, access.
 */
int
vlabel_priv_grant(struct ucred *cred, int priv)
{

	return (EPERM);
}
