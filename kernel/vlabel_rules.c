/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Rule Engine
 *
 * Manages the rule table and evaluates access decisions.
 * Pattern matching is in vlabel_match.c.
 * Syscall handlers are in vlabel_syscall.c.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/rwlock.h>
#include <sys/sysctl.h>

#include <machine/atomic.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"
#include "vlabel_dtrace.h"

/*
 * Rule table storage
 *
 * vlabel_rule_count: number of non-NULL rules (for stats/limits)
 * vlabel_rule_end: index after last rule (for iteration bounds)
 *
 * Rules are appended at vlabel_rule_end. Removals leave holes (NULL).
 * Iteration must scan 0..vlabel_rule_end-1, skipping NULLs.
 */
struct vlabel_rule *vlabel_rules[VLABEL_MAX_RULES];
int vlabel_rule_count;
int vlabel_rule_end;
struct rwlock vlabel_rules_lock;

/*
 * Statistics - accessed atomically via atomic_add_64()
 */
uint64_t vlabel_checks;
uint64_t vlabel_allowed;
uint64_t vlabel_denied;

/*
 * Label statistics - defined in mac_vlabel.c
 */
extern uint64_t vlabel_labels_read;
extern uint64_t vlabel_labels_default;

/*
 * Next rule ID counter
 */
uint32_t vlabel_next_rule_id = 1;

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
	vlabel_rule_end = 0;

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
			if (rule->vr_newlabel != NULL)
				free(rule->vr_newlabel, M_TEMP);
			free(rule, M_TEMP);
		}
	}
	vlabel_rule_count = 0;
	rw_wunlock(&vlabel_rules_lock);

	rw_destroy(&vlabel_rules_lock);
}

/*
 * Evaluate rules against an access request
 *
 * Returns:
 *   0 = allowed
 *   EACCES = denied
 *
 * Uses first-match semantics. If no rule matches, uses default policy.
 *
 * obj_proc is optional - only needed for proc operations (debug/signal/sched)
 * to enable object context checking. Pass NULL for vnode operations.
 */
int
vlabel_rules_check(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj, uint32_t op, struct proc *obj_proc)
{
	const struct vlabel_rule *rule;
	int i, result;
	uint32_t matched_rule_id = 0;

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

	for (i = 0; i < vlabel_rule_end; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		if (vlabel_rule_matches(rule, subj, obj, op, cred, obj_proc)) {
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

	for (i = 0; i < vlabel_rule_end; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		/* Only check EXEC operations for transitions */
		if ((rule->vr_operations & VLABEL_OP_EXEC) == 0)
			continue;

		if (rule->vr_action != VLABEL_ACTION_TRANSITION)
			continue;

		/* Transitions don't need object context (no target process) */
		if (vlabel_rule_matches(rule, subj, obj, VLABEL_OP_EXEC, cred, NULL)) {
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

	for (i = 0; i < vlabel_rule_end; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		/* Only check EXEC operations for transitions */
		if ((rule->vr_operations & VLABEL_OP_EXEC) == 0)
			continue;

		if (rule->vr_action != VLABEL_ACTION_TRANSITION)
			continue;

		/* Transitions don't need object context (no target process) */
		if (vlabel_rule_matches(rule, subj, obj, VLABEL_OP_EXEC, cred, NULL)) {
			if (rule->vr_newlabel != NULL) {
				vlabel_label_copy(rule->vr_newlabel, newlabel);
				result = 0;
				VLABEL_DPRINTF("get_transition: rule %u -> '%s'",
				    rule->vr_id, newlabel->vl_raw);
			}
			break;
		}
	}

	rw_runlock(&vlabel_rules_lock);
	return (result);
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
			if (rule->vr_newlabel != NULL)
				free(rule->vr_newlabel, M_TEMP);
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
			if (rule->vr_newlabel != NULL)
				free(rule->vr_newlabel, M_TEMP);
			free(rule, M_TEMP);
			cleared++;
		}
	}

	vlabel_rule_count = 0;
	vlabel_rule_end = 0;

	rw_wunlock(&vlabel_rules_lock);

	/* DTrace: rules cleared */
	SDT_PROBE1(vlabel, rules, rule, clear, cleared);

	(void)cleared;

	VLABEL_DPRINTF("rules_clear: all rules cleared");
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
