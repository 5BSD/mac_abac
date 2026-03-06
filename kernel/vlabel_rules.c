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
 * Hardcoded test rule: Deny exec of type=untrusted
 * This is loaded at init for MVP testing.
 */
static struct vlabel_rule vlabel_test_rule = {
	.vr_id = 1,
	.vr_action = VLABEL_ACTION_DENY,
	.vr_operations = VLABEL_OP_EXEC,
	.vr_subject = {
		.vp_flags = 0,		/* Match any subject */
		.vp_type = "",
		.vp_domain = "",
		.vp_name = "",
		.vp_level = "",
	},
	.vr_object = {
		.vp_flags = VLABEL_MATCH_TYPE,	/* Match type=untrusted */
		.vp_type = "untrusted",
		.vp_domain = "",
		.vp_name = "",
		.vp_level = "",
	},
	.vr_context = {
		.vc_flags = 0,		/* No context constraints */
	},
};

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

	/*
	 * Load hardcoded test rule for MVP.
	 * In future, rules will be loaded via /dev/vlabel or syscall.
	 */
	vlabel_rules[0] = &vlabel_test_rule;
	vlabel_rule_count = 1;

	VLABEL_DPRINTF("rule engine initialized with %d test rules",
	    vlabel_rule_count);
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
			/* Don't free the hardcoded test rule */
			if (rule != &vlabel_test_rule)
				free(rule, M_TEMP);
		}
	}
	vlabel_rule_count = 0;
	rw_wunlock(&vlabel_rules_lock);

	rw_destroy(&vlabel_rules_lock);
}

/*
 * Check if a label matches a pattern
 */
static bool
vlabel_pattern_match(const struct vlabel_label *label,
    const struct vlabel_pattern *pattern)
{
	bool match = true;

	/* If no flags set, match everything (wildcard) */
	if ((pattern->vp_flags & ~VLABEL_MATCH_NEGATE) == 0)
		return (true);

	/* Check each requested field */
	if (pattern->vp_flags & VLABEL_MATCH_TYPE) {
		if (pattern->vp_type[0] != '\0' &&
		    strcmp(label->vl_type, pattern->vp_type) != 0)
			match = false;
	}

	if (pattern->vp_flags & VLABEL_MATCH_DOMAIN) {
		if (pattern->vp_domain[0] != '\0' &&
		    strcmp(label->vl_domain, pattern->vp_domain) != 0)
			match = false;
	}

	if (pattern->vp_flags & VLABEL_MATCH_NAME) {
		if (pattern->vp_name[0] != '\0' &&
		    strcmp(label->vl_name, pattern->vp_name) != 0)
			match = false;
	}

	if (pattern->vp_flags & VLABEL_MATCH_LEVEL) {
		if (pattern->vp_level[0] != '\0' &&
		    strcmp(label->vl_level, pattern->vp_level) != 0)
			match = false;
	}

	/* Apply negation if requested */
	if (pattern->vp_flags & VLABEL_MATCH_NEGATE)
		match = !match;

	return (match);
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
	 * For MVP, default is ALLOW (permissive).
	 * In production, default should be DENY.
	 */
	result = 0;
	VLABEL_DPRINTF("rules_check: no rule matched, default ALLOW "
	    "subj='%s' obj='%s' op=0x%x",
	    subj->vl_raw, obj->vl_raw, op);

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

			/* Don't free if it's the hardcoded test rule */
			if (rule != &vlabel_test_rule)
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
			/* Don't free the hardcoded test rule */
			if (rule != &vlabel_test_rule)
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
	stats->vs_labels_read = 0;	/* TODO: get from label module */
	stats->vs_labels_default = 0;
	stats->vs_rule_count = vlabel_rule_count;
	rw_runlock(&vlabel_rules_lock);
}
