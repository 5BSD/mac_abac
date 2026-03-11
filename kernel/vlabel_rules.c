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
 * Rule set management
 *
 * vlabel_set_enabled: Bitmap tracking which sets are enabled (8KB for 65536 sets)
 * vlabel_active_sets: Sorted list of sets that have rules (for efficient iteration)
 * vlabel_active_set_count: Number of entries in active_sets
 *
 * Evaluation iterates through active_sets in order (set 0 first, then 1, etc.)
 * and skips disabled sets. This provides IPFW-style set semantics with PF-style
 * ordered evaluation.
 */
uint8_t vlabel_set_enabled[VLABEL_SET_BITMAP_SIZE];
uint16_t vlabel_active_sets[VLABEL_MAX_RULES];	/* Max distinct sets = max rules */
uint16_t vlabel_active_set_count;

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

	/* Initialize set management - all sets enabled by default */
	memset(vlabel_set_enabled, 0xFF, sizeof(vlabel_set_enabled));
	vlabel_active_set_count = 0;

	vlabel_checks = 0;
	vlabel_allowed = 0;
	vlabel_denied = 0;

}

/*
 * Destroy rule subsystem
 */
void
vlabel_rules_destroy(void)
{
	struct vlabel_rule *rule;
	int i;

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
 * Uses first-match semantics with set-ordered evaluation.
 * Sets are evaluated in ascending order (set 0 first, then 1, etc.).
 * Within each set, rules are evaluated in the order they were added.
 * Disabled sets are skipped entirely.
 * If no rule matches, uses default policy.
 *
 * obj_proc is optional - only needed for proc operations (debug/signal/sched)
 * to enable object context checking. Pass NULL for vnode operations.
 */
int
vlabel_rules_check(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj, uint32_t op, struct proc *obj_proc)
{
	const struct vlabel_rule *rule;
	int i, si, result;
	uint16_t set;
	uint32_t matched_rule_id = 0;

	atomic_add_64(&vlabel_checks, 1);

	/* Safety checks */
	if (subj == NULL || obj == NULL) {
		atomic_add_64(&vlabel_allowed, 1);
		return (0);
	}

	/* DTrace: check entry */
	SDT_PROBE3(vlabel, rules, check, entry, subj->vl_raw, obj->vl_raw, op);

	rw_rlock(&vlabel_rules_lock);

	result = EACCES;	/* Default deny */

	/* Iterate sets in ascending order */
	for (si = 0; si < vlabel_active_set_count; si++) {
		set = vlabel_active_sets[si];

		/* Skip disabled sets */
		if (!VLABEL_SET_IS_ENABLED(set))
			continue;

		/* Evaluate rules in this set */
		for (i = 0; i < vlabel_rule_end; i++) {
			rule = vlabel_rules[i];
			if (rule == NULL)
				continue;

			/* Only consider rules in the current set */
			if (rule->vr_set != set)
				continue;

			if (vlabel_rule_matches(rule, subj, obj, op, cred, obj_proc)) {
				/* DTrace: rule matched */
				SDT_PROBE3(vlabel, rules, rule, match,
				    rule->vr_id, rule->vr_action, op);
				matched_rule_id = rule->vr_id;

				if (rule->vr_action == VLABEL_ACTION_ALLOW ||
				    rule->vr_action == VLABEL_ACTION_TRANSITION)
					result = 0;
				else
					result = EACCES;
				goto out;
			}
		}
	}

	/*
	 * No rule matched - use default policy.
	 */
	SDT_PROBE2(vlabel, rules, rule, nomatch, vlabel_default_policy, op);

	if (vlabel_default_policy == 0)
		result = 0;
	else
		result = EACCES;

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
 * Uses set-ordered evaluation (set 0 first, then 1, etc.).
 */
bool
vlabel_rules_will_transition(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj)
{
	const struct vlabel_rule *rule;
	bool result = false;
	int i, si;
	uint16_t set;

	if (subj == NULL || obj == NULL)
		return (false);

	rw_rlock(&vlabel_rules_lock);

	/* Iterate sets in ascending order */
	for (si = 0; si < vlabel_active_set_count; si++) {
		set = vlabel_active_sets[si];

		/* Skip disabled sets */
		if (!VLABEL_SET_IS_ENABLED(set))
			continue;

		for (i = 0; i < vlabel_rule_end; i++) {
			rule = vlabel_rules[i];
			if (rule == NULL)
				continue;

			/* Only consider rules in the current set */
			if (rule->vr_set != set)
				continue;

			/* Only check EXEC operations for transitions */
			if ((rule->vr_operations & VLABEL_OP_EXEC) == 0)
				continue;

			if (rule->vr_action != VLABEL_ACTION_TRANSITION)
				continue;

			/* Transitions don't need object context (no target process) */
			if (vlabel_rule_matches(rule, subj, obj, VLABEL_OP_EXEC, cred, NULL)) {
				result = true;
				goto out;
			}
		}
	}

out:
	rw_runlock(&vlabel_rules_lock);
	return (result);
}

/*
 * Get the new label for a transition
 *
 * Returns 0 and copies the new label if a TRANSITION rule matches,
 * returns ENOENT if no transition rule matches.
 * Uses set-ordered evaluation (set 0 first, then 1, etc.).
 */
int
vlabel_rules_get_transition(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj, struct vlabel_label *newlabel)
{
	const struct vlabel_rule *rule;
	int i, si, result = ENOENT;
	uint16_t set;

	if (subj == NULL || obj == NULL || newlabel == NULL)
		return (EINVAL);

	rw_rlock(&vlabel_rules_lock);

	/* Iterate sets in ascending order */
	for (si = 0; si < vlabel_active_set_count; si++) {
		set = vlabel_active_sets[si];

		/* Skip disabled sets */
		if (!VLABEL_SET_IS_ENABLED(set))
			continue;

		for (i = 0; i < vlabel_rule_end; i++) {
			rule = vlabel_rules[i];
			if (rule == NULL)
				continue;

			/* Only consider rules in the current set */
			if (rule->vr_set != set)
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
				}
				goto out;
			}
		}
	}

out:
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
	vlabel_active_set_count = 0;	/* Reset active sets */

	rw_wunlock(&vlabel_rules_lock);

	/* DTrace: rules cleared */
	SDT_PROBE1(vlabel, rules, rule, clear, cleared);

	(void)cleared;

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
 * ============================================================
 * Set Management Functions
 * ============================================================
 */

/*
 * Rebuild the active_sets array by scanning all rules
 * Must be called with vlabel_rules_lock held for writing
 */
void
vlabel_rebuild_active_sets(void)
{
	const struct vlabel_rule *rule;
	uint16_t sets_seen[VLABEL_MAX_RULES];
	int nsets = 0;
	int i, j, k;
	uint16_t temp;
	bool found;

	/* Collect all unique sets */
	for (i = 0; i < vlabel_rule_end; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		/* Check if we've seen this set */
		found = false;
		for (j = 0; j < nsets; j++) {
			if (sets_seen[j] == rule->vr_set) {
				found = true;
				break;
			}
		}

		if (!found && nsets < VLABEL_MAX_RULES)
			sets_seen[nsets++] = rule->vr_set;
	}

	/* Sort sets in ascending order (simple insertion sort) */
	for (i = 1; i < nsets; i++) {
		temp = sets_seen[i];
		k = i - 1;
		while (k >= 0 && sets_seen[k] > temp) {
			sets_seen[k + 1] = sets_seen[k];
			k--;
		}
		sets_seen[k + 1] = temp;
	}

	/* Copy to active_sets */
	for (i = 0; i < nsets; i++)
		vlabel_active_sets[i] = sets_seen[i];
	vlabel_active_set_count = nsets;
}

/*
 * Enable a range of sets
 */
void
vlabel_set_enable_range(uint16_t start, uint16_t end)
{
	uint16_t s;

	rw_wlock(&vlabel_rules_lock);
	for (s = start; s <= end; s++)
		VLABEL_SET_ENABLE(s);
	rw_wunlock(&vlabel_rules_lock);
}

/*
 * Disable a range of sets
 */
void
vlabel_set_disable_range(uint16_t start, uint16_t end)
{
	uint16_t s;

	rw_wlock(&vlabel_rules_lock);
	for (s = start; s <= end; s++)
		VLABEL_SET_DISABLE(s);
	rw_wunlock(&vlabel_rules_lock);
}

/*
 * Swap two sets atomically
 * All rules in set_a become set_b and vice versa
 */
int
vlabel_set_swap(uint16_t set_a, uint16_t set_b)
{
	struct vlabel_rule *rule;
	int i;
	bool enabled_a, enabled_b;

	if (set_a == set_b)
		return (0);

	rw_wlock(&vlabel_rules_lock);

	/* Swap set numbers on all affected rules */
	for (i = 0; i < vlabel_rule_end; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		if (rule->vr_set == set_a)
			rule->vr_set = set_b;
		else if (rule->vr_set == set_b)
			rule->vr_set = set_a;
	}

	/* Swap enabled state */
	enabled_a = VLABEL_SET_IS_ENABLED(set_a);
	enabled_b = VLABEL_SET_IS_ENABLED(set_b);

	if (enabled_a)
		VLABEL_SET_ENABLE(set_b);
	else
		VLABEL_SET_DISABLE(set_b);

	if (enabled_b)
		VLABEL_SET_ENABLE(set_a);
	else
		VLABEL_SET_DISABLE(set_a);

	/* Rebuild active sets (set numbers changed but list is still valid) */
	vlabel_rebuild_active_sets();

	rw_wunlock(&vlabel_rules_lock);
	return (0);
}

/*
 * Move all rules from one set to another
 */
int
vlabel_set_move(uint16_t from_set, uint16_t to_set)
{
	struct vlabel_rule *rule;
	int i;

	if (from_set == to_set)
		return (0);

	rw_wlock(&vlabel_rules_lock);

	for (i = 0; i < vlabel_rule_end; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		if (rule->vr_set == from_set)
			rule->vr_set = to_set;
	}

	vlabel_rebuild_active_sets();

	rw_wunlock(&vlabel_rules_lock);
	return (0);
}

/*
 * Clear all rules in a specific set
 */
void
vlabel_set_clear(uint16_t set)
{
	struct vlabel_rule *rule;
	int i;
	uint32_t cleared = 0;

	rw_wlock(&vlabel_rules_lock);

	for (i = 0; i < vlabel_rule_end; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		if (rule->vr_set == set) {
			vlabel_rules[i] = NULL;
			vlabel_rule_count--;
			if (rule->vr_newlabel != NULL)
				free(rule->vr_newlabel, M_TEMP);
			free(rule, M_TEMP);
			cleared++;
		}
	}

	vlabel_rebuild_active_sets();

	rw_wunlock(&vlabel_rules_lock);

	(void)cleared;
}

/*
 * Get information about sets
 * Caller provides range to query, we fill in rule counts and enabled status
 */
void
vlabel_set_get_info(struct vlabel_set_list_arg *arg)
{
	const struct vlabel_rule *rule;
	uint32_t calc_end;
	uint16_t s, end_set;
	int i, idx;

	if (arg->vsl_count == 0 || arg->vsl_count > 256)
		arg->vsl_count = 256;

	/* Calculate end_set avoiding uint16_t overflow */
	calc_end = (uint32_t)arg->vsl_start + arg->vsl_count - 1;
	if (calc_end >= VLABEL_MAX_SETS)
		end_set = VLABEL_MAX_SETS - 1;
	else
		end_set = (uint16_t)calc_end;

	/* Zero out results */
	memset(arg->vsl_rule_counts, 0, sizeof(arg->vsl_rule_counts));
	memset(arg->vsl_enabled, 0, sizeof(arg->vsl_enabled));

	rw_rlock(&vlabel_rules_lock);

	/* Count rules per set */
	for (i = 0; i < vlabel_rule_end; i++) {
		rule = vlabel_rules[i];
		if (rule == NULL)
			continue;

		s = rule->vr_set;
		if (s >= arg->vsl_start && s <= end_set) {
			idx = s - arg->vsl_start;
			if (idx < 256)
				arg->vsl_rule_counts[idx]++;
		}
	}

	/* Copy enabled bits for the queried range */
	for (s = arg->vsl_start; s <= end_set; s++) {
		idx = s - arg->vsl_start;
		if (idx < 256 && VLABEL_SET_IS_ENABLED(s))
			arg->vsl_enabled[idx / 8] |= (1 << (idx % 8));
	}

	rw_runlock(&vlabel_rules_lock);
}
