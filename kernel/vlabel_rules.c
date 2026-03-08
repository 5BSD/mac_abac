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

	atomic_add_64(&vlabel_checks, 1);

	/* Safety checks */
	if (subj == NULL || obj == NULL) {
		VLABEL_DPRINTF("rules_check: NULL label, allowing");
		atomic_add_64(&vlabel_allowed, 1);
		return (0);
	}

	rw_rlock(&vlabel_rules_lock);

	result = EACCES;	/* Default deny */

	for (i = 0; i < vlabel_rule_count; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		if (vlabel_rule_matches(rule, subj, obj, op, cred)) {
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

	if (result == 0)
		atomic_add_64(&vlabel_allowed, 1);
	else
		atomic_add_64(&vlabel_denied, 1);

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
 * Add a rule to the table
 *
 * Returns:
 *   0 = success
 *   ENOSPC = table full
 *   ENOMEM = allocation failed
 */
int
vlabel_rule_add(struct vlabel_rule *rule)
{
	struct vlabel_rule *newrule;
	int i;

	/* Allocate a copy */
	newrule = malloc(sizeof(*newrule), M_TEMP, M_NOWAIT);
	if (newrule == NULL)
		return (ENOMEM);

	memcpy(newrule, rule, sizeof(*newrule));

	rw_wlock(&vlabel_rules_lock);

	/* Find empty slot */
	for (i = 0; i < VLABEL_MAX_RULES; i++) {
		if (vlabel_rules[i] == NULL) {
			vlabel_rules[i] = newrule;
			vlabel_rule_count++;
			rw_wunlock(&vlabel_rules_lock);
			VLABEL_DPRINTF("rule_add: added rule %u at slot %d",
			    newrule->vr_id, i);
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

	VLABEL_DPRINTF("rules_clear: all rules cleared");
}

/*
 * Get statistics for ioctl
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
 * Convert kernel rule to IO structure for userland
 */
static void
vlabel_rule_to_io(const struct vlabel_rule *rule, struct vlabel_rule_io *io)
{

	memset(io, 0, sizeof(*io));

	io->vr_id = rule->vr_id;
	io->vr_action = rule->vr_action;
	io->vr_operations = rule->vr_operations;

	/* Serialize subject pattern to string */
	io->vr_subject.vp_flags = rule->vr_subject.vp_flags;
	vlabel_pattern_to_string(&rule->vr_subject, io->vr_subject.vp_pattern,
	    sizeof(io->vr_subject.vp_pattern));

	/* Serialize object pattern to string */
	io->vr_object.vp_flags = rule->vr_object.vp_flags;
	vlabel_pattern_to_string(&rule->vr_object, io->vr_object.vp_pattern,
	    sizeof(io->vr_object.vp_pattern));

	/* Copy context constraints */
	io->vr_context.vc_flags = rule->vr_context.vc_flags;
	io->vr_context.vc_cap_sandboxed = rule->vr_context.vc_cap_sandboxed;
	io->vr_context.vc_has_tty = rule->vr_context.vc_has_tty;
	io->vr_context.vc_jail_check = rule->vr_context.vc_jail_check;
	io->vr_context.vc_uid = rule->vr_context.vc_uid;
	io->vr_context.vc_gid = rule->vr_context.vc_gid;

	/* Copy newlabel for TRANSITION rules */
	if (rule->vr_action == VLABEL_ACTION_TRANSITION) {
		strlcpy(io->vr_newlabel, rule->vr_newlabel.vl_raw,
		    sizeof(io->vr_newlabel));
	}
}

/*
 * List rules to userland buffer
 *
 * The caller provides a vlabel_rule_list_io header followed by space
 * for vrl_count vlabel_rule_io structures.
 *
 * On return:
 *   vrl_count = number of rules actually copied
 *   vrl_total = total rules in kernel
 */
int
vlabel_rules_list(struct vlabel_rule_list_io *list_io,
    struct vlabel_rule_io *rules_out, uint32_t max_rules)
{
	const struct vlabel_rule *rule;
	uint32_t copied = 0;
	uint32_t offset;
	int i, slot;

	if (list_io == NULL)
		return (EINVAL);

	offset = list_io->vrl_offset;

	rw_rlock(&vlabel_rules_lock);

	list_io->vrl_total = vlabel_rule_count;

	/* Skip to offset */
	slot = 0;
	for (i = 0; i < VLABEL_MAX_RULES && slot < offset; i++) {
		if (vlabel_rules[i] != NULL)
			slot++;
	}

	/* Copy rules starting from offset */
	for (; i < VLABEL_MAX_RULES && copied < max_rules; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		if (rules_out != NULL)
			vlabel_rule_to_io(rule, &rules_out[copied]);

		copied++;
	}

	list_io->vrl_count = copied;

	rw_runlock(&vlabel_rules_lock);

	VLABEL_DPRINTF("rules_list: returned %u/%u rules (offset=%u)",
	    copied, list_io->vrl_total, offset);

	return (0);
}

/*
 * Test if an access would be allowed without actually performing it
 *
 * This is useful for policy debugging and "what-if" analysis.
 */
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

int
vlabel_rules_test_access(struct vlabel_test_io *test_io)
{
	struct vlabel_label subj_label, obj_label;
	char converted[VLABEL_MAX_LABEL_LEN];
	const struct vlabel_rule *rule;
	int i;

	if (test_io == NULL)
		return (EINVAL);

	/* Parse the subject label (convert from comma-separated to newline) */
	memset(&subj_label, 0, sizeof(subj_label));
	if (test_io->vt_subject_label[0] != '\0') {
		convert_label_format(test_io->vt_subject_label,
		    converted, sizeof(converted));
		vlabel_label_parse(converted, strlen(converted), &subj_label);
		VLABEL_DPRINTF("test_access: parsed subj '%s' -> npairs=%u",
		    test_io->vt_subject_label, subj_label.vl_npairs);
	}

	/* Parse the object label (convert from comma-separated to newline) */
	memset(&obj_label, 0, sizeof(obj_label));
	if (test_io->vt_object_label[0] != '\0') {
		convert_label_format(test_io->vt_object_label,
		    converted, sizeof(converted));
		vlabel_label_parse(converted, strlen(converted), &obj_label);
		VLABEL_DPRINTF("test_access: parsed obj '%s' -> npairs=%u",
		    test_io->vt_object_label, obj_label.vl_npairs);
	}

	test_io->vt_result = EACCES;	/* Default deny */
	test_io->vt_rule_id = 0;	/* No matching rule */

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
		if ((rule->vr_operations & test_io->vt_operation) == 0) {
			VLABEL_DPRINTF("test_access: rule %u op mismatch", rule->vr_id);
			continue;
		}

		/* Check subject pattern */
		if (!vlabel_pattern_match(&subj_label, &rule->vr_subject)) {
			VLABEL_DPRINTF("test_access: rule %u subj mismatch", rule->vr_id);
			continue;
		}

		/* Check object pattern */
		if (!vlabel_pattern_match(&obj_label, &rule->vr_object)) {
			VLABEL_DPRINTF("test_access: rule %u obj mismatch", rule->vr_id);
			continue;
		}

		/* Note: We skip context matching in test mode since
		 * we don't have a real credential to test against */

		/* Rule matches */
		VLABEL_DPRINTF("test_access: rule %u MATCHED action=%u",
		    rule->vr_id, rule->vr_action);
		test_io->vt_rule_id = rule->vr_id;
		if (rule->vr_action == VLABEL_ACTION_ALLOW ||
		    rule->vr_action == VLABEL_ACTION_TRANSITION) {
			test_io->vt_result = 0;
		} else {
			test_io->vt_result = EACCES;
		}
		goto out;
	}

	/* No rule matched - use default policy */
	test_io->vt_result = vlabel_default_policy ? EACCES : 0;
	test_io->vt_rule_id = 0;

out:
	rw_runlock(&vlabel_rules_lock);

	VLABEL_DPRINTF("test_access: subj='%s' obj='%s' op=0x%x -> %s (rule %u)",
	    test_io->vt_subject_label, test_io->vt_object_label,
	    test_io->vt_operation,
	    test_io->vt_result == 0 ? "ALLOW" : "DENY",
	    test_io->vt_rule_id);

	return (0);
}
