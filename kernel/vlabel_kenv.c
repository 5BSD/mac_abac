/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Kernel Environment Checks
 *
 * Controls access to kernel environment variables (kenv).
 * These are boot-time and runtime kernel parameters.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * Synthetic label for kenv objects
 */
static struct vlabel_label vlabel_kenv_object = {
	.vl_raw = "type=kenv\n",
	.vl_npairs = 1,
	.vl_pairs = {
		{ .vp_key = "type", .vp_value = "kenv" }
	}
};

/*
 * vlabel_kenv_check_dump - Check if subject can dump all kenv variables
 *
 * Controls kenv(2) with KENV_DUMP.
 */
int
vlabel_kenv_check_dump(struct ucred *cred)
{
	struct vlabel_label *subj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);

	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	error = vlabel_rules_check(cred, subj, &vlabel_kenv_object,
	    VLABEL_OP_READ, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * vlabel_kenv_check_get - Check if subject can get a kenv variable
 *
 * Controls kenv(2) with KENV_GET.
 */
int
vlabel_kenv_check_get(struct ucred *cred, char *name)
{
	struct vlabel_label *subj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);

	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	error = vlabel_rules_check(cred, subj, &vlabel_kenv_object,
	    VLABEL_OP_READ, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * vlabel_kenv_check_set - Check if subject can set a kenv variable
 *
 * Controls kenv(2) with KENV_SET.
 */
int
vlabel_kenv_check_set(struct ucred *cred, char *name, char *value)
{
	struct vlabel_label *subj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);

	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	error = vlabel_rules_check(cred, subj, &vlabel_kenv_object,
	    VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * vlabel_kenv_check_unset - Check if subject can unset a kenv variable
 *
 * Controls kenv(2) with KENV_UNSET.
 */
int
vlabel_kenv_check_unset(struct ucred *cred, char *name)
{
	struct vlabel_label *subj;
	int error;

	VLABEL_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);

	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	error = vlabel_rules_check(cred, subj, &vlabel_kenv_object,
	    VLABEL_OP_WRITE, NULL);

	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}
