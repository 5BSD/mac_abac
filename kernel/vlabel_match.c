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
 * Check if a label matches a pattern (large pattern struct)
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
 * Check if a label matches a compact rule pattern
 *
 * This function matches a label against the compact vlabel_rule_pattern
 * structure used in rules. It has the same semantics as vlabel_label_match
 * but operates on the smaller rule pattern structure.
 *
 * Pattern matching rules:
 * - Empty pattern (npairs=0) = wildcard (matches anything)
 * - Each pattern pair must exist in the label
 * - Pattern value "*" matches any value for that key
 * - VLABEL_MATCH_NEGATE inverts the result
 */
bool
vlabel_rule_pattern_match(const struct vlabel_label *label,
    const struct vlabel_rule_pattern *pattern)
{
	const char *label_value;
	uint32_t i;
	bool match = true;

	if (label == NULL || pattern == NULL)
		return (false);

	/* Empty pattern matches everything */
	if (pattern->vrp_npairs == 0) {
		match = true;
		goto done;
	}

	/* Check each pattern pair against the label */
	for (i = 0; i < pattern->vrp_npairs && match; i++) {
		const struct vlabel_rule_pair *rp = &pattern->vrp_pairs[i];

		/* Find this key in the label */
		label_value = vlabel_label_get_value(label, rp->vrp_key);

		if (label_value == NULL) {
			/* Key not found in label - no match */
			match = false;
		} else if (strcmp(rp->vrp_value, "*") != 0) {
			/* Not a wildcard - must match exactly */
			if (strcmp(label_value, rp->vrp_value) != 0)
				match = false;
		}
		/* else: wildcard "*" matches any value - continue */
	}

done:
	/* Handle negation */
	if (pattern->vrp_flags & VLABEL_MATCH_NEGATE)
		match = !match;

	return (match);
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
		return (false);
	}

	if (check_cred == NULL) {
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
			/*
			 * Object: check target process's credential for capmode.
			 * Hold a reference to the credential to prevent it from
			 * being freed while we're checking it.
			 */
			struct ucred *proc_cred;
			PROC_LOCK(proc);
			proc_cred = proc->p_ucred;
			if (proc_cred != NULL)
				crhold(proc_cred);
			PROC_UNLOCK(proc);
			if (proc_cred != NULL) {
				is_sandboxed = (proc_cred->cr_flags & CRED_FLAG_CAPMODE) != 0;
				crfree(proc_cred);
			}
		}

		if (is_sandboxed != ctx->vc_cap_sandboxed)
			return (false);
	}

	/* Check jail context */
	if (ctx->vc_flags & VLABEL_CTX_JAIL) {
		int jailid = 0;
		if (check_cred->cr_prison != NULL)
			jailid = check_cred->cr_prison->pr_id;

		switch (ctx->vc_jail_check) {
		case 0:
			/* Must be on host (jail 0) */
			if (jailid != 0)
				return (false);
			break;
		case -1:
			/* Must be in any jail (not host) */
			if (jailid == 0)
				return (false);
			break;
		default:
			/* Must be in specific jail */
			if (jailid != ctx->vc_jail_check)
				return (false);
			break;
		}
	}

	/* Check effective UID */
	if (ctx->vc_flags & VLABEL_CTX_UID) {
		if (check_cred->cr_uid != ctx->vc_uid)
			return (false);
	}

	/* Check effective GID */
	if (ctx->vc_flags & VLABEL_CTX_GID) {
		if (check_cred->cr_gid != ctx->vc_gid)
			return (false);
	}

	/* Check real UID */
	if (ctx->vc_flags & VLABEL_CTX_RUID) {
		if (check_cred->cr_ruid != ctx->vc_uid)
			return (false);
	}

	/* Check session/login context - via process's session */
	if (ctx->vc_flags & VLABEL_CTX_HAS_TTY) {
		bool has_tty = false;

		/*
		 * Access session pointer under process lock to avoid
		 * race conditions with session changes.
		 */
		if (check_proc != NULL) {
			PROC_LOCK(check_proc);
			if (check_proc->p_session != NULL)
				has_tty = (check_proc->p_session->s_ttyp != NULL);
			PROC_UNLOCK(check_proc);
		}

		if (has_tty != ctx->vc_has_tty)
			return (false);
	}

	return (true);
}

/*
 * Check if a rule matches the current access request
 *
 * subj_cred: credential of the subject (caller) - used for subject context
 * obj_proc: target process for proc operations - used for object context (may be NULL)
 *
 * Uses vlabel_rule_pattern_match for the compact rule pattern structures.
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

	/* Check subject pattern (uses compact rule pattern) */
	if (!vlabel_rule_pattern_match(subj, &rule->vr_subject))
		return (false);

	/* Check object pattern (uses compact rule pattern) */
	if (!vlabel_rule_pattern_match(obj, &rule->vr_object))
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
		size_t needed, copied;

		if (i > 0 && pos < buflen - 1)
			buf[pos++] = ',';

		/* Calculate space needed for "key=value" */
		needed = strlen(pair->vp_key) + 1 + strlen(pair->vp_value);
		if (pos + needed >= buflen)
			break;

		/*
		 * strlcpy returns total length it tried to copy, not actual.
		 * Clamp position to avoid buffer overflow on truncation.
		 */
		copied = strlcpy(buf + pos, pair->vp_key, buflen - pos);
		pos = (pos + copied >= buflen) ? buflen - 1 : pos + copied;
		if (pos < buflen - 1)
			buf[pos++] = '=';
		copied = strlcpy(buf + pos, pair->vp_value, buflen - pos);
		pos = (pos + copied >= buflen) ? buflen - 1 : pos + copied;
	}

	return (pos);
}

/*
 * Serialize a compact rule pattern to a string
 *
 * Converts the parsed key=value pairs back to a comma-separated string.
 * Returns the number of characters written (not including null terminator).
 */
size_t
vlabel_rule_pattern_to_string(const struct vlabel_rule_pattern *pattern,
    char *buf, size_t buflen)
{
	size_t pos = 0;
	uint32_t i;

	if (buf == NULL || buflen == 0)
		return (0);

	buf[0] = '\0';

	/* Empty pattern = wildcard */
	if (pattern->vrp_npairs == 0) {
		if (buflen > 1) {
			buf[0] = '*';
			buf[1] = '\0';
			return (1);
		}
		return (0);
	}

	/* Build comma-separated key=value string */
	for (i = 0; i < pattern->vrp_npairs && pos < buflen - 1; i++) {
		const struct vlabel_rule_pair *pair = &pattern->vrp_pairs[i];
		size_t needed, copied;

		if (i > 0 && pos < buflen - 1)
			buf[pos++] = ',';

		/* Calculate space needed for "key=value" */
		needed = strlen(pair->vrp_key) + 1 + strlen(pair->vrp_value);
		if (pos + needed >= buflen)
			break;

		copied = strlcpy(buf + pos, pair->vrp_key, buflen - pos);
		pos = (pos + copied >= buflen) ? buflen - 1 : pos + copied;
		if (pos < buflen - 1)
			buf[pos++] = '=';
		copied = strlcpy(buf + pos, pair->vrp_value, buflen - pos);
		pos = (pos + copied >= buflen) ? buflen - 1 : pos + copied;
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
