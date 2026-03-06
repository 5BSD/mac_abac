/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Process Checks
 *
 * Handles process-related access checks and privilege grants.
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
 * Process checks - STUBS (always allow)
 */

int
vlabel_proc_check_debug(struct ucred *cred, struct proc *p)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_proc_check_sched(struct ucred *cred, struct proc *p)
{

	VLABEL_CHECK_ENABLED();
	return (0);
}

int
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
int
vlabel_priv_grant(struct ucred *cred, int priv)
{

	return (EPERM);
}
