/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Rule Engine
 *
 * Manages the rule table and evaluates access decisions based on
 * subject/object labels and operation types.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/capsicum.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>

#include <machine/atomic.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"
#include "vlabel_dtrace.h"

/*
 * Rule table storage
 */
static struct vlabel_rule *vlabel_rules[VLABEL_MAX_RULES];
static int vlabel_rule_count;
static struct rwlock vlabel_rules_lock;

/*
 * Statistics - accessed atomically via atomic_add_64()
 */
static uint64_t vlabel_checks;
static uint64_t vlabel_allowed;
static uint64_t vlabel_denied;

/*
 * Label statistics - defined in mac_vlabel.c
 */
extern uint64_t vlabel_labels_read;
extern uint64_t vlabel_labels_default;

SYSCTL_DECL(_security_mac_vlabel);

SYSCTL_UQUAD(_security_mac_vlabel, OID_AUTO, checks, CTLFLAG_RD,
    &vlabel_checks, 0, "Total access checks");

SYSCTL_UQUAD(_security_mac_vlabel, OID_AUTO, allowed, CTLFLAG_RD,
    &vlabel_allowed, 0, "Allowed accesses");

SYSCTL_UQUAD(_security_mac_vlabel, OID_AUTO, denied, CTLFLAG_RD,
    &vlabel_denied, 0, "Denied accesses");

SYSCTL_INT(_security_mac_vlabel, OID_AUTO, rule_count, CTLFLAG_RD,
    &vlabel_rule_count, 0, "Number of active rules");

/*
 * Default policy when no rule matches
 * 0 = allow (permissive default)
 * 1 = deny (secure default)
 */
int vlabel_default_policy = 0;

SYSCTL_INT(_security_mac_vlabel, OID_AUTO, default_policy, CTLFLAG_RW,
    &vlabel_default_policy, 0,
    "Default policy when no rule matches (0=allow, 1=deny)");

/*
 * Initialize rule subsystem
 */
void
vlabel_rules_init(void)
{

	rw_init(&vlabel_rules_lock, "vlabel rules");
	memset(vlabel_rules, 0, sizeof(vlabel_rules));
	vlabel_rule_count = 0;

	vlabel_checks = 0;
	vlabel_allowed = 0;
	vlabel_denied = 0;

	VLABEL_DPRINTF("rule engine initialized");
}

/*
 * Destroy rule subsystem
 */
void
vlabel_rules_destroy(void)
{
	struct vlabel_rule *rule;
	int i;

	VLABEL_DPRINTF("rule engine destroyed (rules=%d, checks=%ju, denied=%ju)",
	    vlabel_rule_count,
	    (uintmax_t)vlabel_checks,
	    (uintmax_t)vlabel_denied);

	/* Free all dynamically allocated rules */
	rw_wlock(&vlabel_rules_lock);
	for (i = 0; i < VLABEL_MAX_RULES; i++) {
		rule = vlabel_rules[i];
		if (rule != NULL) {
			vlabel_rules[i] = NULL;
			free(rule, M_TEMP);
		}
	}
	vlabel_rule_count = 0;
	rw_wunlock(&vlabel_rules_lock);

	rw_destroy(&vlabel_rules_lock);
}

/*
 * Check if a label matches a pattern
 *
 * This is a wrapper around vlabel_label_match from vlabel_label.c.
 * The actual matching logic supports arbitrary key=value pairs.
 */
static bool
vlabel_pattern_match(const struct vlabel_label *label,
    const struct vlabel_pattern *pattern)
{

	return (vlabel_label_match(label, pattern));
}

/*
 * Check if context constraints match the current credential
 *
 * Context constraints allow rules to be conditional on:
 * - Capability mode (sandboxed or not)
 * - Jail context (host, specific jail, or any jail)
 * - User ID (effective UID)
 * - Group ID (effective GID)
 * - Real UID
 * - Session ID
 * - Whether process has a controlling TTY
 */
static bool
vlabel_context_matches(const struct vlabel_context *ctx, struct ucred *cred)
{
	struct thread *td;

	/* If no context flags set, match everything */
	if (ctx->vc_flags == 0)
		return (true);

	/* Need valid credential for all checks */
	if (cred == NULL)
		return (false);

	/* Check capability mode (sandboxed) */
	if (ctx->vc_flags & VLABEL_CTX_CAP_SANDBOXED) {
		td = curthread;
		if (td != NULL) {
			bool is_sandboxed = IN_CAPABILITY_MODE(td);
			if (is_sandboxed != ctx->vc_cap_sandboxed) {
				VLABEL_DPRINTF("context: cap_sandboxed mismatch "
				    "(want %d, got %d)",
				    ctx->vc_cap_sandboxed, is_sandboxed);
				return (false);
			}
		}
	}

	/* Check jail context */
	if (ctx->vc_flags & VLABEL_CTX_JAIL) {
		int jailid = 0;
		if (cred->cr_prison != NULL)
			jailid = cred->cr_prison->pr_id;

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
		if (cred->cr_uid != ctx->vc_uid) {
			VLABEL_DPRINTF("context: uid mismatch "
			    "(want %u, got %u)", ctx->vc_uid, cred->cr_uid);
			return (false);
		}
	}

	/* Check effective GID */
	if (ctx->vc_flags & VLABEL_CTX_GID) {
		if (cred->cr_gid != ctx->vc_gid) {
			VLABEL_DPRINTF("context: gid mismatch "
			    "(want %u, got %u)", ctx->vc_gid, cred->cr_gid);
			return (false);
		}
	}

	/* Check real UID */
	if (ctx->vc_flags & VLABEL_CTX_RUID) {
		if (cred->cr_ruid != ctx->vc_uid) {
			VLABEL_DPRINTF("context: ruid mismatch "
			    "(want %u, got %u)", ctx->vc_uid, cred->cr_ruid);
			return (false);
		}
	}

	/* Check session/login context - via process's session */
	if (ctx->vc_flags & VLABEL_CTX_HAS_TTY) {
		struct proc *p = curproc;
		bool has_tty = false;

		if (p != NULL && p->p_session != NULL)
			has_tty = (p->p_session->s_ttyp != NULL);

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
 */
static bool
vlabel_rule_matches(const struct vlabel_rule *rule,
    const struct vlabel_label *subj,
    const struct vlabel_label *obj,
    uint32_t op,
    struct ucred *cred)
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

	/* Check context constraints (jail, capability mode, etc.) */
	if (!vlabel_context_matches(&rule->vr_context, cred))
		return (false);

	return (true);
}

/*
 * Evaluate rules against an access request
 *
 * Returns:
 *   0 = allowed
 *   EACCES = denied
 *
 * Uses first-match semantics. If no rule matches, default is DENY.
 */
int
vlabel_rules_check(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj, uint32_t op)
{
	const struct vlabel_rule *rule;
	int i, result;
	uint32_t matched_rule_id = 0;	/* Used by DTrace probes */

	atomic_add_64(&vlabel_checks, 1);

	/* Safety checks */
	if (subj == NULL || obj == NULL) {
		VLABEL_DPRINTF("rules_check: NULL label, allowing");
		atomic_add_64(&vlabel_allowed, 1);
		return (0);
	}

	/* DTrace: check entry */
	SDT_PROBE3(vlabel, rules, check, entry, subj->vl_raw, obj->vl_raw, op);

	rw_rlock(&vlabel_rules_lock);

	result = EACCES;	/* Default deny */

	for (i = 0; i < vlabel_rule_count; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		if (vlabel_rule_matches(rule, subj, obj, op, cred)) {
			/* DTrace: rule matched */
			SDT_PROBE3(vlabel, rules, rule, match,
			    rule->vr_id, rule->vr_action, op);
			matched_rule_id = rule->vr_id;

			if (rule->vr_action == VLABEL_ACTION_ALLOW ||
			    rule->vr_action == VLABEL_ACTION_TRANSITION) {
				result = 0;
				VLABEL_DPRINTF("rules_check: rule %u %s "
				    "subj='%s' obj='%s' op=0x%x",
				    rule->vr_id,
				    rule->vr_action == VLABEL_ACTION_TRANSITION ?
				        "TRANSITION" : "ALLOW",
				    subj->vl_raw, obj->vl_raw, op);
			} else {
				result = EACCES;
				VLABEL_DPRINTF("rules_check: rule %u DENY "
				    "subj='%s' obj='%s' op=0x%x",
				    rule->vr_id, subj->vl_raw, obj->vl_raw, op);
			}
			goto out;
		}
	}

	/*
	 * No rule matched - use default policy.
	 * Controlled by sysctl security.mac.vlabel.default_policy
	 */
	SDT_PROBE2(vlabel, rules, rule, nomatch, vlabel_default_policy, op);

	if (vlabel_default_policy == 0) {
		result = 0;
		VLABEL_DPRINTF("rules_check: no rule matched, default ALLOW "
		    "subj='%s' obj='%s' op=0x%x",
		    subj->vl_raw, obj->vl_raw, op);
	} else {
		result = EACCES;
		VLABEL_DPRINTF("rules_check: no rule matched, default DENY "
		    "subj='%s' obj='%s' op=0x%x",
		    subj->vl_raw, obj->vl_raw, op);
	}

out:
	rw_runlock(&vlabel_rules_lock);

	/* DTrace: check-allow or check-deny */
	if (result == 0) {
		SDT_PROBE4(vlabel, rules, check, allow,
		    subj->vl_raw, obj->vl_raw, op, matched_rule_id);
		atomic_add_64(&vlabel_allowed, 1);
	} else {
		SDT_PROBE4(vlabel, rules, check, deny,
		    subj->vl_raw, obj->vl_raw, op, matched_rule_id);
		atomic_add_64(&vlabel_denied, 1);
	}

	/* DTrace: check return */
	SDT_PROBE2(vlabel, rules, check, return, result, op);

	(void)matched_rule_id;	/* Silence warning when DTrace compiled out */

	return (result);
}

/*
 * Check if exec will cause a label transition
 *
 * Returns true if a TRANSITION rule matches, false otherwise.
 */
bool
vlabel_rules_will_transition(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj)
{
	const struct vlabel_rule *rule;
	bool result = false;
	int i;

	if (subj == NULL || obj == NULL)
		return (false);

	rw_rlock(&vlabel_rules_lock);

	for (i = 0; i < vlabel_rule_count; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		/* Only check EXEC operations for transitions */
		if ((rule->vr_operations & VLABEL_OP_EXEC) == 0)
			continue;

		if (rule->vr_action != VLABEL_ACTION_TRANSITION)
			continue;

		if (vlabel_rule_matches(rule, subj, obj, VLABEL_OP_EXEC, cred)) {
			result = true;
			VLABEL_DPRINTF("will_transition: rule %u matches "
			    "subj='%s' obj='%s'",
			    rule->vr_id, subj->vl_raw, obj->vl_raw);
			break;
		}
	}

	rw_runlock(&vlabel_rules_lock);
	return (result);
}

/*
 * Get the new label for a transition
 *
 * Returns 0 and copies the new label if a TRANSITION rule matches,
 * returns ENOENT if no transition rule matches.
 */
int
vlabel_rules_get_transition(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj, struct vlabel_label *newlabel)
{
	const struct vlabel_rule *rule;
	int i, result = ENOENT;

	if (subj == NULL || obj == NULL || newlabel == NULL)
		return (EINVAL);

	rw_rlock(&vlabel_rules_lock);

	for (i = 0; i < vlabel_rule_count; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		/* Only check EXEC operations for transitions */
		if ((rule->vr_operations & VLABEL_OP_EXEC) == 0)
			continue;

		if (rule->vr_action != VLABEL_ACTION_TRANSITION)
			continue;

		if (vlabel_rule_matches(rule, subj, obj, VLABEL_OP_EXEC, cred)) {
			vlabel_label_copy(&rule->vr_newlabel, newlabel);
			result = 0;
			VLABEL_DPRINTF("get_transition: rule %u -> '%s'",
			    rule->vr_id, newlabel->vl_raw);
			break;
		}
	}

	rw_runlock(&vlabel_rules_lock);
	return (result);
}

/*
 * Convert comma-separated label string to newline-separated format
 *
 * CLI users provide labels like "type=user,domain=web" but vlabel_label_parse
 * expects newline-separated format like "type=user\ndomain=web\n".
 */
static void
convert_label_format(const char *src, char *dst, size_t dstlen)
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

/*
 * Next rule ID counter
 */
static uint32_t vlabel_next_rule_id = 1;

/*
 * Add a rule from syscall argument
 *
 * The data buffer contains variable-length strings:
 *   subject[vr_subject_len], object[vr_object_len], newlabel[vr_newlabel_len]
 *
 * Returns:
 *   0 = success
 *   ENOSPC = table full
 *   ENOMEM = allocation failed
 *   EINVAL = invalid arguments
 */
int
vlabel_rule_add_from_arg(struct vlabel_rule_arg *arg, const char *data)
{
	struct vlabel_rule *newrule;
	const char *subject_str, *object_str, *newlabel_str;
	char *converted;
	int i, error;

	if (arg == NULL || data == NULL)
		return (EINVAL);

	/* Validate action */
	if (arg->vr_action > VLABEL_ACTION_TRANSITION)
		return (EINVAL);

	/* Extract string pointers from data buffer */
	subject_str = data;
	object_str = data + arg->vr_subject_len;
	newlabel_str = data + arg->vr_subject_len + arg->vr_object_len;

	/*
	 * Allocate conversion buffer dynamically - 4KB is too large
	 * for the kernel stack.
	 */
	converted = malloc(VLABEL_MAX_LABEL_LEN, M_TEMP, M_WAITOK);

	/* Allocate the rule */
	newrule = malloc(sizeof(*newrule), M_TEMP, M_NOWAIT | M_ZERO);
	if (newrule == NULL) {
		free(converted, M_TEMP);
		return (ENOMEM);
	}

	/* Fill in basic fields */
	newrule->vr_action = arg->vr_action;
	newrule->vr_operations = arg->vr_operations;

	/* Parse subject pattern */
	newrule->vr_subject.vp_flags = arg->vr_subject_flags;
	if (arg->vr_subject_len > 0 && subject_str[0] != '\0' &&
	    subject_str[0] != '*') {
		/* Note: vlabel_pattern_parse expects comma-separated format,
		 * which is what the CLI sends - no conversion needed */
		error = vlabel_pattern_parse(subject_str, strlen(subject_str),
		    &newrule->vr_subject);
		if (error) {
			VLABEL_DPRINTF("rule_add: failed to parse subject '%s'",
			    subject_str);
			free(newrule, M_TEMP);
			free(converted, M_TEMP);
			return (error);
		}
	}
	/* else: empty pattern = wildcard (npairs=0) */

	/* Parse object pattern */
	newrule->vr_object.vp_flags = arg->vr_object_flags;
	if (arg->vr_object_len > 0 && object_str[0] != '\0' &&
	    object_str[0] != '*') {
		/* Note: vlabel_pattern_parse expects comma-separated format,
		 * which is what the CLI sends - no conversion needed */
		error = vlabel_pattern_parse(object_str, strlen(object_str),
		    &newrule->vr_object);
		if (error) {
			VLABEL_DPRINTF("rule_add: failed to parse object '%s'",
			    object_str);
			free(newrule, M_TEMP);
			free(converted, M_TEMP);
			return (error);
		}
	}

	/* Copy context constraints */
	newrule->vr_context.vc_flags = arg->vr_context.vc_flags;
	newrule->vr_context.vc_cap_sandboxed = arg->vr_context.vc_cap_sandboxed;
	newrule->vr_context.vc_has_tty = arg->vr_context.vc_has_tty;
	newrule->vr_context.vc_jail_check = arg->vr_context.vc_jail_check;
	newrule->vr_context.vc_uid = arg->vr_context.vc_uid;
	newrule->vr_context.vc_gid = arg->vr_context.vc_gid;

	/* Parse newlabel for TRANSITION rules */
	if (arg->vr_action == VLABEL_ACTION_TRANSITION &&
	    arg->vr_newlabel_len > 0 && newlabel_str[0] != '\0') {
		convert_label_format(newlabel_str, converted, VLABEL_MAX_LABEL_LEN);
		error = vlabel_label_parse(converted, strlen(converted),
		    &newrule->vr_newlabel);
		if (error) {
			VLABEL_DPRINTF("rule_add: failed to parse newlabel '%s'",
			    newlabel_str);
			free(newrule, M_TEMP);
			free(converted, M_TEMP);
			return (error);
		}
	}

	/* Done with conversion buffer */
	free(converted, M_TEMP);

	rw_wlock(&vlabel_rules_lock);

	/* Assign rule ID */
	newrule->vr_id = vlabel_next_rule_id++;

	/* Find empty slot */
	for (i = 0; i < VLABEL_MAX_RULES; i++) {
		if (vlabel_rules[i] == NULL) {
			vlabel_rules[i] = newrule;
			vlabel_rule_count++;
			/* Return assigned ID to caller */
			arg->vr_id = newrule->vr_id;
			rw_wunlock(&vlabel_rules_lock);
			/* DTrace: rule added */
			SDT_PROBE3(vlabel, rules, rule, add,
			    newrule->vr_id, newrule->vr_action,
			    newrule->vr_operations);
			VLABEL_DPRINTF("rule_add: added rule %u at slot %d "
			    "action=%u ops=0x%x",
			    newrule->vr_id, i, newrule->vr_action,
			    newrule->vr_operations);
			return (0);
		}
	}

	rw_wunlock(&vlabel_rules_lock);
	free(newrule, M_TEMP);
	return (ENOSPC);
}

/*
 * Remove a rule by ID
 *
 * Returns:
 *   0 = success
 *   ENOENT = rule not found
 */
int
vlabel_rule_remove(uint32_t id)
{
	struct vlabel_rule *rule;
	int i;

	rw_wlock(&vlabel_rules_lock);

	for (i = 0; i < VLABEL_MAX_RULES; i++) {
		rule = vlabel_rules[i];
		if (rule != NULL && rule->vr_id == id) {
			vlabel_rules[i] = NULL;
			vlabel_rule_count--;
			rw_wunlock(&vlabel_rules_lock);
			/* DTrace: rule removed */
			SDT_PROBE1(vlabel, rules, rule, remove, id);
			free(rule, M_TEMP);
			VLABEL_DPRINTF("rule_remove: removed rule %u", id);
			return (0);
		}
	}

	rw_wunlock(&vlabel_rules_lock);
	return (ENOENT);
}

/*
 * Clear all rules
 */
void
vlabel_rules_clear(void)
{
	struct vlabel_rule *rule;
	int i;
	uint32_t cleared = 0;

	rw_wlock(&vlabel_rules_lock);

	for (i = 0; i < VLABEL_MAX_RULES; i++) {
		rule = vlabel_rules[i];
		if (rule != NULL) {
			vlabel_rules[i] = NULL;
			free(rule, M_TEMP);
			cleared++;
		}
	}

	vlabel_rule_count = 0;

	rw_wunlock(&vlabel_rules_lock);

	/* DTrace: rules cleared */
	SDT_PROBE1(vlabel, rules, rule, clear, cleared);

	(void)cleared;	/* Silence warning when DTrace compiled out */

	VLABEL_DPRINTF("rules_clear: all rules cleared");
}

/*
 * Internal: add a rule without locking (caller holds write lock)
 */
static int
vlabel_rule_add_locked(struct vlabel_rule_arg *arg, const char *data)
{
	struct vlabel_rule *newrule;
	const char *subject_str, *object_str, *newlabel_str;
	char *converted;
	int i, error;

	if (arg == NULL || data == NULL)
		return (EINVAL);

	/* Validate action */
	if (arg->vr_action > VLABEL_ACTION_TRANSITION)
		return (EINVAL);

	/* Extract string pointers from data buffer */
	subject_str = data;
	object_str = data + arg->vr_subject_len;
	newlabel_str = data + arg->vr_subject_len + arg->vr_object_len;

	converted = malloc(VLABEL_MAX_LABEL_LEN, M_TEMP, M_WAITOK);

	newrule = malloc(sizeof(*newrule), M_TEMP, M_NOWAIT | M_ZERO);
	if (newrule == NULL) {
		free(converted, M_TEMP);
		return (ENOMEM);
	}

	newrule->vr_action = arg->vr_action;
	newrule->vr_operations = arg->vr_operations;

	/* Parse subject pattern */
	newrule->vr_subject.vp_flags = arg->vr_subject_flags;
	if (arg->vr_subject_len > 0 && subject_str[0] != '\0' &&
	    subject_str[0] != '*') {
		error = vlabel_pattern_parse(subject_str, strlen(subject_str),
		    &newrule->vr_subject);
		if (error) {
			free(newrule, M_TEMP);
			free(converted, M_TEMP);
			return (error);
		}
	}

	/* Parse object pattern */
	newrule->vr_object.vp_flags = arg->vr_object_flags;
	if (arg->vr_object_len > 0 && object_str[0] != '\0' &&
	    object_str[0] != '*') {
		error = vlabel_pattern_parse(object_str, strlen(object_str),
		    &newrule->vr_object);
		if (error) {
			free(newrule, M_TEMP);
			free(converted, M_TEMP);
			return (error);
		}
	}

	/* Copy context constraints */
	newrule->vr_context.vc_flags = arg->vr_context.vc_flags;
	newrule->vr_context.vc_cap_sandboxed = arg->vr_context.vc_cap_sandboxed;
	newrule->vr_context.vc_has_tty = arg->vr_context.vc_has_tty;
	newrule->vr_context.vc_jail_check = arg->vr_context.vc_jail_check;
	newrule->vr_context.vc_uid = arg->vr_context.vc_uid;
	newrule->vr_context.vc_gid = arg->vr_context.vc_gid;

	/* Parse newlabel for TRANSITION rules */
	if (arg->vr_action == VLABEL_ACTION_TRANSITION &&
	    arg->vr_newlabel_len > 0 && newlabel_str[0] != '\0') {
		convert_label_format(newlabel_str, converted, VLABEL_MAX_LABEL_LEN);
		error = vlabel_label_parse(converted, strlen(converted),
		    &newrule->vr_newlabel);
		if (error) {
			free(newrule, M_TEMP);
			free(converted, M_TEMP);
			return (error);
		}
	}

	free(converted, M_TEMP);

	/* Assign rule ID */
	newrule->vr_id = vlabel_next_rule_id++;

	/* Find empty slot */
	for (i = 0; i < VLABEL_MAX_RULES; i++) {
		if (vlabel_rules[i] == NULL) {
			vlabel_rules[i] = newrule;
			vlabel_rule_count++;
			SDT_PROBE3(vlabel, rules, rule, add,
			    newrule->vr_id, newrule->vr_action,
			    newrule->vr_operations);
			return (0);
		}
	}

	free(newrule, M_TEMP);
	return (ENOSPC);
}

/*
 * Atomic rule load - replace all rules at once (like PF reload)
 *
 * Buffer format: packed vlabel_rule_arg structures with variable data.
 * Each entry is: struct vlabel_rule_arg + subject + object + newlabel
 *
 * On success: old rules cleared, new rules loaded atomically.
 * On failure: old rules unchanged.
 */
int
vlabel_rules_load(struct vlabel_rule_load_arg *load_arg)
{
	struct vlabel_rule *old_rules[VLABEL_MAX_RULES];
	int old_count;
	char *kbuf;
	size_t offset;
	uint32_t i, loaded;
	int error;

	if (load_arg == NULL)
		return (EINVAL);

	if (load_arg->vrl_count > VLABEL_MAX_RULES)
		return (E2BIG);

	if (load_arg->vrl_buf == NULL || load_arg->vrl_buflen == 0) {
		/* Empty load = clear all rules */
		vlabel_rules_clear();
		load_arg->vrl_loaded = 0;
		return (0);
	}

	/* Copy buffer from userland */
	kbuf = malloc(load_arg->vrl_buflen, M_TEMP, M_WAITOK);
	error = copyin(load_arg->vrl_buf, kbuf, load_arg->vrl_buflen);
	if (error) {
		free(kbuf, M_TEMP);
		return (error);
	}

	rw_wlock(&vlabel_rules_lock);

	/* Save old rules in case we need to rollback */
	old_count = vlabel_rule_count;
	for (i = 0; i < VLABEL_MAX_RULES; i++) {
		old_rules[i] = vlabel_rules[i];
		vlabel_rules[i] = NULL;
	}
	vlabel_rule_count = 0;

	/* Parse and add new rules */
	offset = 0;
	loaded = 0;
	error = 0;

	for (i = 0; i < load_arg->vrl_count && offset < load_arg->vrl_buflen; i++) {
		struct vlabel_rule_arg *arg;
		const char *data;
		size_t rule_size;

		if (offset + sizeof(struct vlabel_rule_arg) > load_arg->vrl_buflen) {
			error = EINVAL;
			break;
		}

		arg = (struct vlabel_rule_arg *)(kbuf + offset);
		data = kbuf + offset + sizeof(struct vlabel_rule_arg);

		/* Calculate total size of this rule entry */
		rule_size = sizeof(struct vlabel_rule_arg) +
		    arg->vr_subject_len + arg->vr_object_len + arg->vr_newlabel_len;

		if (offset + rule_size > load_arg->vrl_buflen) {
			error = EINVAL;
			break;
		}

		error = vlabel_rule_add_locked(arg, data);
		if (error) {
			VLABEL_DPRINTF("rules_load: failed to add rule %u: %d",
			    i, error);
			break;
		}

		loaded++;
		offset += rule_size;
	}

	if (error) {
		/* Rollback: restore old rules */
		for (i = 0; i < VLABEL_MAX_RULES; i++) {
			if (vlabel_rules[i] != NULL)
				free(vlabel_rules[i], M_TEMP);
			vlabel_rules[i] = old_rules[i];
		}
		vlabel_rule_count = old_count;
		VLABEL_DPRINTF("rules_load: rollback, restored %d rules", old_count);
	} else {
		/* Success: free old rules */
		for (i = 0; i < VLABEL_MAX_RULES; i++) {
			if (old_rules[i] != NULL)
				free(old_rules[i], M_TEMP);
		}
		VLABEL_DPRINTF("rules_load: loaded %u rules atomically", loaded);
	}

	rw_wunlock(&vlabel_rules_lock);

	free(kbuf, M_TEMP);

	load_arg->vrl_loaded = loaded;
	return (error);
}

/*
 * Get statistics (via mac_syscall)
 */
void
vlabel_rules_get_stats(struct vlabel_stats *stats)
{

	rw_rlock(&vlabel_rules_lock);
	stats->vs_checks = vlabel_checks;
	stats->vs_allowed = vlabel_allowed;
	stats->vs_denied = vlabel_denied;
	stats->vs_labels_read = vlabel_labels_read;
	stats->vs_labels_default = vlabel_labels_default;
	stats->vs_rule_count = vlabel_rule_count;
	rw_runlock(&vlabel_rules_lock);
}

/*
 * Serialize a pattern structure to a string
 *
 * Converts the parsed key=value pairs back to a comma-separated string.
 * Returns the number of characters written (not including null terminator).
 */
static size_t
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
 * Calculate the size needed to serialize a rule
 */
static size_t
vlabel_rule_out_size(const struct vlabel_rule *rule)
{
	char subj_buf[VLABEL_MAX_LABEL_LEN];
	char obj_buf[VLABEL_MAX_LABEL_LEN];
	size_t subj_len, obj_len, newlabel_len;

	subj_len = vlabel_pattern_to_string(&rule->vr_subject, subj_buf,
	    sizeof(subj_buf)) + 1;
	obj_len = vlabel_pattern_to_string(&rule->vr_object, obj_buf,
	    sizeof(obj_buf)) + 1;
	newlabel_len = (rule->vr_action == VLABEL_ACTION_TRANSITION) ?
	    strlen(rule->vr_newlabel.vl_raw) + 1 : 0;

	return sizeof(struct vlabel_rule_out) + subj_len + obj_len + newlabel_len;
}

/*
 * Serialize a rule to userland buffer
 *
 * Returns the number of bytes written.
 */
static size_t
vlabel_rule_serialize(const struct vlabel_rule *rule, char *buf, size_t buflen)
{
	struct vlabel_rule_out *out = (struct vlabel_rule_out *)buf;
	char *data;
	size_t subj_len, obj_len, newlabel_len, total;

	/* Calculate string lengths */
	char subj_buf[VLABEL_MAX_LABEL_LEN];
	char obj_buf[VLABEL_MAX_LABEL_LEN];

	subj_len = vlabel_pattern_to_string(&rule->vr_subject, subj_buf,
	    sizeof(subj_buf)) + 1;
	obj_len = vlabel_pattern_to_string(&rule->vr_object, obj_buf,
	    sizeof(obj_buf)) + 1;
	newlabel_len = (rule->vr_action == VLABEL_ACTION_TRANSITION) ?
	    strlen(rule->vr_newlabel.vl_raw) + 1 : 0;

	total = sizeof(struct vlabel_rule_out) + subj_len + obj_len + newlabel_len;
	if (total > buflen)
		return (0);

	/* Fill header */
	memset(out, 0, sizeof(*out));
	out->vr_id = rule->vr_id;
	out->vr_action = rule->vr_action;
	out->vr_operations = rule->vr_operations;
	out->vr_subject_flags = rule->vr_subject.vp_flags;
	out->vr_object_flags = rule->vr_object.vp_flags;
	out->vr_context.vc_flags = rule->vr_context.vc_flags;
	out->vr_context.vc_cap_sandboxed = rule->vr_context.vc_cap_sandboxed;
	out->vr_context.vc_has_tty = rule->vr_context.vc_has_tty;
	out->vr_context.vc_jail_check = rule->vr_context.vc_jail_check;
	out->vr_context.vc_uid = rule->vr_context.vc_uid;
	out->vr_context.vc_gid = rule->vr_context.vc_gid;
	out->vr_subject_len = subj_len;
	out->vr_object_len = obj_len;
	out->vr_newlabel_len = newlabel_len;

	/* Copy strings */
	data = buf + sizeof(struct vlabel_rule_out);
	memcpy(data, subj_buf, subj_len);
	data += subj_len;
	memcpy(data, obj_buf, obj_len);
	data += obj_len;
	if (newlabel_len > 0)
		memcpy(data, rule->vr_newlabel.vl_raw, newlabel_len);

	return (total);
}

/*
 * List rules to userland buffer
 *
 * If vrl_buf is NULL, just returns the total count and required buffer size.
 * Otherwise, serializes rules into the buffer.
 *
 * On return:
 *   vrl_count = number of rules actually copied
 *   vrl_total = total rules in kernel
 */
int
vlabel_rules_list(struct vlabel_rule_list_arg *list_arg)
{
	const struct vlabel_rule *rule;
	uint32_t copied = 0;
	uint32_t offset;
	size_t buf_used = 0;
	char *kbuf = NULL;
	int i, slot, error = 0;

	if (list_arg == NULL)
		return (EINVAL);

	offset = list_arg->vrl_offset;

	/* Allocate kernel buffer if userland buffer provided */
	if (list_arg->vrl_buf != NULL && list_arg->vrl_buflen > 0) {
		kbuf = malloc(list_arg->vrl_buflen, M_TEMP, M_WAITOK);
	}

	rw_rlock(&vlabel_rules_lock);

	list_arg->vrl_total = vlabel_rule_count;

	/* Skip to offset */
	slot = 0;
	for (i = 0; i < VLABEL_MAX_RULES && slot < (int)offset; i++) {
		if (vlabel_rules[i] != NULL)
			slot++;
	}

	/* Serialize rules starting from offset */
	for (; i < VLABEL_MAX_RULES; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		if (kbuf != NULL) {
			size_t needed = vlabel_rule_out_size(rule);
			if (buf_used + needed > list_arg->vrl_buflen)
				break;

			size_t written = vlabel_rule_serialize(rule,
			    kbuf + buf_used, list_arg->vrl_buflen - buf_used);
			if (written == 0)
				break;
			buf_used += written;
		}
		copied++;
	}

	list_arg->vrl_count = copied;

	rw_runlock(&vlabel_rules_lock);

	/* Copy buffer to userland */
	if (kbuf != NULL && buf_used > 0) {
		error = copyout(kbuf, list_arg->vrl_buf, buf_used);
	}

	if (kbuf != NULL)
		free(kbuf, M_TEMP);

	VLABEL_DPRINTF("rules_list: returned %u/%u rules (offset=%u bufused=%zu)",
	    copied, list_arg->vrl_total, offset, buf_used);

	return (error);
}

/*
 * Test if an access would be allowed without actually performing it
 *
 * This is useful for policy debugging and "what-if" analysis.
 * Subject and object are null-terminated strings.
 */
int
vlabel_rules_test_access(const char *subject, size_t subject_len,
    const char *object, size_t object_len, uint32_t operation,
    uint32_t *result, uint32_t *rule_id)
{
	struct vlabel_label *subj_label, *obj_label;
	char *converted;
	const struct vlabel_rule *rule;
	int i, error;

	if (result == NULL)
		return (EINVAL);

	/*
	 * Allocate labels dynamically - struct vlabel_label is ~9KB each,
	 * which is too large for the kernel stack (typically 8-16KB).
	 */
	subj_label = malloc(sizeof(*subj_label), M_TEMP, M_WAITOK | M_ZERO);
	obj_label = malloc(sizeof(*obj_label), M_TEMP, M_WAITOK | M_ZERO);
	converted = malloc(VLABEL_MAX_LABEL_LEN, M_TEMP, M_WAITOK);

	error = 0;

	/* Parse the subject label (convert from comma-separated to newline) */
	if (subject != NULL && subject_len > 0 && subject[0] != '\0') {
		convert_label_format(subject, converted, VLABEL_MAX_LABEL_LEN);
		vlabel_label_parse(converted, strlen(converted), subj_label);
		VLABEL_DPRINTF("test_access: parsed subj '%s' -> npairs=%u",
		    subject, subj_label->vl_npairs);
	}

	/* Parse the object label (convert from comma-separated to newline) */
	if (object != NULL && object_len > 0 && object[0] != '\0') {
		convert_label_format(object, converted, VLABEL_MAX_LABEL_LEN);
		vlabel_label_parse(converted, strlen(converted), obj_label);
		VLABEL_DPRINTF("test_access: parsed obj '%s' -> npairs=%u",
		    object, obj_label->vl_npairs);
	}

	*result = EACCES;		/* Default deny */
	if (rule_id != NULL)
		*rule_id = 0;		/* No matching rule */

	rw_rlock(&vlabel_rules_lock);

	VLABEL_DPRINTF("test_access: checking %u rules", vlabel_rule_count);

	for (i = 0; i < VLABEL_MAX_RULES; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		VLABEL_DPRINTF("test_access: rule[%d] id=%u action=%u ops=0x%x "
		    "subj_npairs=%u obj_npairs=%u",
		    i, rule->vr_id, rule->vr_action, rule->vr_operations,
		    rule->vr_subject.vp_npairs, rule->vr_object.vp_npairs);

		/* Check if operation is covered by this rule */
		if ((rule->vr_operations & operation) == 0) {
			VLABEL_DPRINTF("test_access: rule %u op mismatch", rule->vr_id);
			continue;
		}

		/* Check subject pattern */
		if (!vlabel_pattern_match(subj_label, &rule->vr_subject)) {
			VLABEL_DPRINTF("test_access: rule %u subj mismatch", rule->vr_id);
			continue;
		}

		/* Check object pattern */
		if (!vlabel_pattern_match(obj_label, &rule->vr_object)) {
			VLABEL_DPRINTF("test_access: rule %u obj mismatch", rule->vr_id);
			continue;
		}

		/* Note: We skip context matching in test mode since
		 * we don't have a real credential to test against */

		/* Rule matches */
		VLABEL_DPRINTF("test_access: rule %u MATCHED action=%u",
		    rule->vr_id, rule->vr_action);
		if (rule_id != NULL)
			*rule_id = rule->vr_id;
		if (rule->vr_action == VLABEL_ACTION_ALLOW ||
		    rule->vr_action == VLABEL_ACTION_TRANSITION) {
			*result = 0;
		} else {
			*result = EACCES;
		}
		goto out;
	}

	/* No rule matched - use default policy */
	*result = vlabel_default_policy ? EACCES : 0;
	if (rule_id != NULL)
		*rule_id = 0;

out:
	rw_runlock(&vlabel_rules_lock);

	VLABEL_DPRINTF("test_access: subj='%s' obj='%s' op=0x%x -> %s (rule %u)",
	    subject ? subject : "(null)", object ? object : "(null)",
	    operation,
	    *result == 0 ? "ALLOW" : "DENY",
	    rule_id ? *rule_id : 0);

	free(converted, M_TEMP);
	free(obj_label, M_TEMP);
	free(subj_label, M_TEMP);

	return (error);
}
