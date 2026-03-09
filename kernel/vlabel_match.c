/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Pattern and Context Matching
 *
 * Handles pattern matching for rules and context constraint evaluation.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/capsicum.h>
#include <sys/jail.h>
#include <sys/proc.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * Check if a label matches a pattern
 *
 * This is a wrapper around vlabel_label_match from vlabel_label.c.
 * The actual matching logic supports arbitrary key=value pairs.
 */
bool
vlabel_pattern_match(const struct vlabel_label *label,
    const struct vlabel_pattern *pattern)
{

	return (vlabel_label_match(label, pattern));
}

/*
 * Check if context constraints match
 *
 * Context constraints allow rules to be conditional on:
 * - Capability mode (sandboxed or not)
 * - Jail context (host, specific jail, or any jail)
 * - User ID (effective UID)
 * - Group ID (effective GID)
 * - Real UID
 * - Session ID
 * - Whether process has a controlling TTY
 *
 * For subject context: pass cred (caller's credential), proc=NULL
 * For object context: pass cred=NULL, proc (target process)
 *
 * At least one of cred or proc must be provided if flags are set.
 */
bool
vlabel_context_matches(const struct vlabel_context *ctx,
    struct ucred *cred, struct proc *proc)
{
	struct ucred *check_cred;
	struct proc *check_proc;

	/* If no context flags set, match everything */
	if (ctx->vc_flags == 0)
		return (true);

	/*
	 * Determine which credential/process to check.
	 * For subject context: use cred (caller)
	 * For object context: use proc's credential (target)
	 */
	if (cred != NULL) {
		check_cred = cred;
		check_proc = curproc;
	} else if (proc != NULL) {
		check_cred = proc->p_ucred;
		check_proc = proc;
	} else {
		/* No context info available, can't match constraints */
		VLABEL_DPRINTF("context: no cred or proc provided");
		return (false);
	}

	if (check_cred == NULL) {
		VLABEL_DPRINTF("context: no credential available");
		return (false);
	}

	/* Check capability mode (sandboxed) */
	if (ctx->vc_flags & VLABEL_CTX_CAP_SANDBOXED) {
		bool is_sandboxed = false;

		/*
		 * For subject context, check curthread.
		 * For object context, check target process flag.
		 */
		if (cred != NULL) {
			/* Subject: check current thread */
			struct thread *td = curthread;
			if (td != NULL)
				is_sandboxed = IN_CAPABILITY_MODE(td);
		} else if (proc != NULL) {
			/* Object: check target process's credential for capmode */
			PROC_LOCK(proc);
			if (proc->p_ucred != NULL)
				is_sandboxed = (proc->p_ucred->cr_flags & CRED_FLAG_CAPMODE) != 0;
			PROC_UNLOCK(proc);
		}

		if (is_sandboxed != ctx->vc_cap_sandboxed) {
			VLABEL_DPRINTF("context: cap_sandboxed mismatch "
			    "(want %d, got %d)",
			    ctx->vc_cap_sandboxed, is_sandboxed);
			return (false);
		}
	}

	/* Check jail context */
	if (ctx->vc_flags & VLABEL_CTX_JAIL) {
		int jailid = 0;
		if (check_cred->cr_prison != NULL)
			jailid = check_cred->cr_prison->pr_id;

		switch (ctx->vc_jail_check) {
		case 0:
			/* Must be on host (jail 0) */
			if (jailid != 0) {
				VLABEL_DPRINTF("context: jail mismatch "
				    "(want host, got jail %d)", jailid);
				return (false);
			}
			break;
		case -1:
			/* Must be in any jail (not host) */
			if (jailid == 0) {
				VLABEL_DPRINTF("context: jail mismatch "
				    "(want any jail, got host)");
				return (false);
			}
			break;
		default:
			/* Must be in specific jail */
			if (jailid != ctx->vc_jail_check) {
				VLABEL_DPRINTF("context: jail mismatch "
				    "(want %d, got %d)",
				    ctx->vc_jail_check, jailid);
				return (false);
			}
			break;
		}
	}

	/* Check effective UID */
	if (ctx->vc_flags & VLABEL_CTX_UID) {
		if (check_cred->cr_uid != ctx->vc_uid) {
			VLABEL_DPRINTF("context: uid mismatch "
			    "(want %u, got %u)", ctx->vc_uid, check_cred->cr_uid);
			return (false);
		}
	}

	/* Check effective GID */
	if (ctx->vc_flags & VLABEL_CTX_GID) {
		if (check_cred->cr_gid != ctx->vc_gid) {
			VLABEL_DPRINTF("context: gid mismatch "
			    "(want %u, got %u)", ctx->vc_gid, check_cred->cr_gid);
			return (false);
		}
	}

	/* Check real UID */
	if (ctx->vc_flags & VLABEL_CTX_RUID) {
		if (check_cred->cr_ruid != ctx->vc_uid) {
			VLABEL_DPRINTF("context: ruid mismatch "
			    "(want %u, got %u)", ctx->vc_uid, check_cred->cr_ruid);
			return (false);
		}
	}

	/* Check session/login context - via process's session */
	if (ctx->vc_flags & VLABEL_CTX_HAS_TTY) {
		bool has_tty = false;

		if (check_proc != NULL && check_proc->p_session != NULL)
			has_tty = (check_proc->p_session->s_ttyp != NULL);

		if (has_tty != ctx->vc_has_tty) {
			VLABEL_DPRINTF("context: tty mismatch "
			    "(want %d, got %d)",
			    ctx->vc_has_tty, has_tty);
			return (false);
		}
	}

	VLABEL_DPRINTF("context: all constraints matched");
	return (true);
}

/*
 * Check if a rule matches the current access request
 *
 * subj_cred: credential of the subject (caller) - used for subject context
 * obj_proc: target process for proc operations - used for object context (may be NULL)
 */
bool
vlabel_rule_matches(const struct vlabel_rule *rule,
    const struct vlabel_label *subj,
    const struct vlabel_label *obj,
    uint32_t op,
    struct ucred *subj_cred,
    struct proc *obj_proc)
{

	/* Check if operation is covered by this rule */
	if ((rule->vr_operations & op) == 0)
		return (false);

	/* Check subject pattern */
	if (!vlabel_pattern_match(subj, &rule->vr_subject))
		return (false);

	/* Check object pattern */
	if (!vlabel_pattern_match(obj, &rule->vr_object))
		return (false);

	/* Check subject context constraints (jail, capability mode, etc.) */
	if (!vlabel_context_matches(&rule->vr_subj_context, subj_cred, NULL))
		return (false);

	/* Check object context constraints (for proc operations) */
	if (!vlabel_context_matches(&rule->vr_obj_context, NULL, obj_proc))
		return (false);

	return (true);
}

/*
 * Serialize a pattern structure to a string
 *
 * Converts the parsed key=value pairs back to a comma-separated string.
 * Returns the number of characters written (not including null terminator).
 */
size_t
vlabel_pattern_to_string(const struct vlabel_pattern *pattern, char *buf,
    size_t buflen)
{
	size_t pos = 0;
	uint32_t i;

	if (buf == NULL || buflen == 0)
		return (0);

	buf[0] = '\0';

	/* Empty pattern = wildcard */
	if (pattern->vp_npairs == 0) {
		if (buflen > 1) {
			buf[0] = '*';
			buf[1] = '\0';
			return (1);
		}
		return (0);
	}

	/* Build comma-separated key=value string */
	for (i = 0; i < pattern->vp_npairs && pos < buflen - 1; i++) {
		const struct vlabel_pair *pair = &pattern->vp_pairs[i];
		size_t needed;

		if (i > 0 && pos < buflen - 1)
			buf[pos++] = ',';

		/* Calculate space needed for "key=value" */
		needed = strlen(pair->vp_key) + 1 + strlen(pair->vp_value);
		if (pos + needed >= buflen)
			break;

		pos += strlcpy(buf + pos, pair->vp_key, buflen - pos);
		if (pos < buflen - 1)
			buf[pos++] = '=';
		pos += strlcpy(buf + pos, pair->vp_value, buflen - pos);
	}

	return (pos);
}

/*
 * Convert comma-separated label string to newline-separated format
 *
 * CLI users provide labels like "type=user,domain=web" but vlabel_label_parse
 * expects newline-separated format like "type=user\ndomain=web\n".
 */
void
vlabel_convert_label_format(const char *src, char *dst, size_t dstlen)
{
	size_t i, j;

	for (i = 0, j = 0; src[i] != '\0' && j < dstlen - 1; i++) {
		if (src[i] == ',')
			dst[j++] = '\n';
		else
			dst[j++] = src[i];
	}
	/* Ensure trailing newline for proper parsing */
	if (j > 0 && j < dstlen - 1 && dst[j - 1] != '\n')
		dst[j++] = '\n';
	dst[j] = '\0';
}
