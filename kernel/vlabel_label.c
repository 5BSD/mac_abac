/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Label Management
 *
 * This file implements label allocation, parsing, and matching for the
 * vLabel MAC policy. Labels are key-value pairs stored in extended
 * attributes and cached in MAC label slots.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>

#include <machine/atomic.h>
#include <vm/uma.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * UMA zone for label allocation
 */
static uma_zone_t vlabel_zone;

/*
 * Statistics counters - accessed atomically via atomic_add_64()
 */
static uint64_t vlabel_labels_allocated;
static uint64_t vlabel_labels_freed;
static uint64_t vlabel_parse_errors;

SYSCTL_DECL(_security_mac_vlabel);
SYSCTL_UQUAD(_security_mac_vlabel, OID_AUTO, labels_allocated, CTLFLAG_RD,
    &vlabel_labels_allocated, 0, "Total labels allocated");
SYSCTL_UQUAD(_security_mac_vlabel, OID_AUTO, labels_freed, CTLFLAG_RD,
    &vlabel_labels_freed, 0, "Total labels freed");
SYSCTL_UQUAD(_security_mac_vlabel, OID_AUTO, parse_errors, CTLFLAG_RD,
    &vlabel_parse_errors, 0, "Label parse errors");

/*
 * vlabel_label_init - Initialize the label subsystem
 *
 * Called during module init to create the UMA zone.
 */
void
vlabel_label_init(void)
{

	vlabel_zone = uma_zcreate("vlabel_label",
	    sizeof(struct vlabel_label),
	    NULL,	/* ctor */
	    NULL,	/* dtor */
	    NULL,	/* init */
	    NULL,	/* fini */
	    UMA_ALIGN_PTR,
	    0);		/* flags */

	if (vlabel_zone == NULL) {
		printf("vlabel: WARNING: unable to create label zone\n");
		return;
	}

	vlabel_labels_allocated = 0;
	vlabel_labels_freed = 0;
	vlabel_parse_errors = 0;

	VLABEL_DPRINTF("label subsystem initialized");
}

/*
 * vlabel_label_destroy - Destroy the label subsystem
 *
 * Called during module unload.
 *
 * NOTE: We do NOT destroy the UMA zone here because:
 * 1. Labels may still be attached to vnodes/creds that haven't been
 *    destroyed yet (MAC framework calls label_destroy callbacks AFTER
 *    mpo_destroy in some cases)
 * 2. uma_zdestroy() requires the zone to be empty and will panic if not
 *
 * This is why the module uses MPC_LOADTIME_FLAG_NOTLATE (no UNLOADOK) -
 * the module is designed to be loaded at boot and never unloaded.
 * This follows the pattern of mac_biba and mac_lomac.
 */
void
vlabel_label_destroy(void)
{

	VLABEL_DPRINTF("label subsystem destroyed (alloc=%ju, freed=%ju)",
	    (uintmax_t)vlabel_labels_allocated,
	    (uintmax_t)vlabel_labels_freed);

	/* Don't destroy the zone - see note above */
}

/*
 * vlabel_label_alloc - Allocate a new label structure
 *
 * @flags: M_WAITOK or M_NOWAIT
 *
 * Returns a zeroed label structure, or NULL if allocation fails
 * (only possible with M_NOWAIT or if zone not yet initialized).
 */
struct vlabel_label *
vlabel_label_alloc(int flags)
{
	struct vlabel_label *vl;

	/* Zone not initialized yet - can happen during early boot */
	if (vlabel_zone == NULL)
		return (NULL);

	vl = uma_zalloc(vlabel_zone, flags | M_ZERO);
	if (vl != NULL)
		atomic_add_64(&vlabel_labels_allocated, 1);

	return (vl);
}

/*
 * vlabel_label_free - Free a label structure
 *
 * @vl: Label to free (may be NULL)
 */
void
vlabel_label_free(struct vlabel_label *vl)
{

	if (vl == NULL)
		return;

	/* Zone not initialized - shouldn't happen but be safe */
	if (vlabel_zone == NULL)
		return;

	uma_zfree(vlabel_zone, vl);
	atomic_add_64(&vlabel_labels_freed, 1);
}

/*
 * vlabel_label_hash - Compute a simple hash of a label string
 *
 * Used for quick inequality checks before doing full string comparisons.
 */
uint32_t
vlabel_label_hash(const char *str, size_t len)
{
	uint32_t hash = 5381;
	size_t i;

	if (str == NULL || len == 0)
		return (0);

	for (i = 0; i < len && str[i] != '\0'; i++)
		hash = ((hash << 5) + hash) + (unsigned char)str[i];

	return (hash);
}

/*
 * parse_kv_pair - Parse a single key=value pair into the pairs array
 *
 * @str: String containing "key=value"
 * @len: Length of string
 * @vl: Label structure to populate
 *
 * Returns 0 on success, error code on failure.
 */
static int
parse_kv_pair(const char *str, size_t len, struct vlabel_label *vl)
{
	struct vlabel_pair *pair;
	const char *eq;
	size_t keylen, valuelen;

	/* Check if we have room for another pair */
	if (vl->vl_npairs >= VLABEL_MAX_PAIRS) {
		VLABEL_DPRINTF("parse_kv_pair: too many pairs (max %d)",
		    VLABEL_MAX_PAIRS);
		return (E2BIG);
	}

	/* Find the '=' separator */
	eq = memchr(str, '=', len);
	if (eq == NULL) {
		VLABEL_DPRINTF("parse_kv_pair: no '=' in pair");
		return (EINVAL);
	}

	keylen = eq - str;
	valuelen = len - keylen - 1;

	/* Validate lengths */
	if (keylen == 0 || keylen >= VLABEL_MAX_KEY_LEN) {
		VLABEL_DPRINTF("parse_kv_pair: key too long (%zu >= %d)",
		    keylen, VLABEL_MAX_KEY_LEN);
		return (EINVAL);
	}
	if (valuelen >= VLABEL_MAX_VALUE_LEN) {
		VLABEL_DPRINTF("parse_kv_pair: value too long (%zu >= %d)",
		    valuelen, VLABEL_MAX_VALUE_LEN);
		return (EINVAL);
	}

	/* Store in the next available pair slot */
	pair = &vl->vl_pairs[vl->vl_npairs];

	memcpy(pair->vp_key, str, keylen);
	pair->vp_key[keylen] = '\0';

	memcpy(pair->vp_value, eq + 1, valuelen);
	pair->vp_value[valuelen] = '\0';

	vl->vl_npairs++;

	return (0);
}

/*
 * vlabel_label_parse - Parse a label string into a label structure
 *
 * @str: Label string in newline-separated format: "key1=val1\nkey2=val2\n"
 * @len: Length of string (not including null terminator)
 * @vl: Label structure to populate (must be zeroed)
 *
 * Returns 0 on success, error code on failure.
 *
 * Example input: "type=system\ndomain=daemon\n"
 */
int
vlabel_label_parse(const char *str, size_t len, struct vlabel_label *vl)
{
	const char *p, *end, *nl;
	int error;

	/* Validate inputs */
	if (str == NULL || vl == NULL)
		return (EINVAL);

	/* Empty string is valid - means unlabeled/default */
	if (len == 0) {
		memset(vl, 0, sizeof(*vl));
		return (0);
	}

	if (len > VLABEL_MAX_LABEL_LEN) {
		atomic_add_64(&vlabel_parse_errors, 1);
		VLABEL_DPRINTF("label too long: %zu > %d", len, VLABEL_MAX_LABEL_LEN);
		return (EINVAL);
	}

	/* Store raw label string */
	strlcpy(vl->vl_raw, str, sizeof(vl->vl_raw));
	vl->vl_hash = vlabel_label_hash(str, len);
	vl->vl_npairs = 0;

	/* Parse newline-separated key=value pairs */
	p = str;
	end = str + len;

	while (p < end) {
		/* Find next newline or end of string */
		nl = memchr(p, '\n', end - p);
		if (nl == NULL)
			nl = end;

		/* Parse this pair (skip empty lines) */
		if (nl > p) {
			error = parse_kv_pair(p, nl - p, vl);
			if (error != 0) {
				atomic_add_64(&vlabel_parse_errors, 1);
				return (error);
			}
		}

		/* Move past newline */
		p = nl + 1;
	}

	VLABEL_DPRINTF("parsed label: raw='%s' npairs=%u",
	    vl->vl_raw, vl->vl_npairs);

	return (0);
}

/*
 * vlabel_label_copy - Copy a label structure
 *
 * @src: Source label
 * @dst: Destination label (must be allocated)
 */
void
vlabel_label_copy(const struct vlabel_label *src, struct vlabel_label *dst)
{

	if (src == NULL || dst == NULL)
		return;

	memcpy(dst, src, sizeof(*dst));
}

/*
 * vlabel_label_set_default - Set a label to default values
 *
 * @vl: Label to initialize
 * @is_subject: true for process labels, false for object labels
 */
void
vlabel_label_set_default(struct vlabel_label *vl, bool is_subject)
{

	if (vl == NULL)
		return;

	memset(vl, 0, sizeof(*vl));

	if (is_subject) {
		strlcpy(vl->vl_raw, "type=user", sizeof(vl->vl_raw));
		vl->vl_npairs = 1;
		strlcpy(vl->vl_pairs[0].vp_key, "type",
		    sizeof(vl->vl_pairs[0].vp_key));
		strlcpy(vl->vl_pairs[0].vp_value, "user",
		    sizeof(vl->vl_pairs[0].vp_value));
	} else {
		strlcpy(vl->vl_raw, "type=unlabeled", sizeof(vl->vl_raw));
		vl->vl_npairs = 1;
		strlcpy(vl->vl_pairs[0].vp_key, "type",
		    sizeof(vl->vl_pairs[0].vp_key));
		strlcpy(vl->vl_pairs[0].vp_value, "unlabeled",
		    sizeof(vl->vl_pairs[0].vp_value));
	}

	vl->vl_hash = vlabel_label_hash(vl->vl_raw, strlen(vl->vl_raw));
}

/*
 * vlabel_label_get_value - Get the value for a key in a label
 *
 * @vl: Label to search
 * @key: Key to look up
 *
 * Returns pointer to value string if found, NULL otherwise.
 * The returned pointer is valid as long as the label is not modified.
 */
const char *
vlabel_label_get_value(const struct vlabel_label *vl, const char *key)
{
	uint32_t i;

	if (vl == NULL || key == NULL)
		return (NULL);

	for (i = 0; i < vl->vl_npairs; i++) {
		if (strcmp(vl->vl_pairs[i].vp_key, key) == 0)
			return (vl->vl_pairs[i].vp_value);
	}

	return (NULL);
}

/*
 * vlabel_label_match - Check if a label matches a pattern
 *
 * @label: Label to check
 * @pattern: Pattern to match against
 *
 * Returns true if label matches pattern, false otherwise.
 *
 * Pattern matching rules:
 * - Empty pattern (npairs=0) = wildcard (matches anything)
 * - Each pattern pair must exist in the label
 * - Pattern value "*" matches any value for that key
 * - VLABEL_MATCH_NEGATE inverts the result
 */
bool
vlabel_label_match(const struct vlabel_label *label,
    const struct vlabel_pattern *pattern)
{
	const char *label_value;
	uint32_t i;
	bool match = true;

	if (label == NULL || pattern == NULL)
		return (false);

	/* Empty pattern matches everything */
	if (pattern->vp_npairs == 0) {
		match = true;
		goto done;
	}

	/* Check each pattern pair against the label */
	for (i = 0; i < pattern->vp_npairs && match; i++) {
		const struct vlabel_pair *pp = &pattern->vp_pairs[i];

		/* Find this key in the label */
		label_value = vlabel_label_get_value(label, pp->vp_key);

		if (label_value == NULL) {
			/* Key not found in label - no match */
			match = false;
		} else if (strcmp(pp->vp_value, "*") != 0) {
			/* Not a wildcard - must match exactly */
			if (strcmp(label_value, pp->vp_value) != 0)
				match = false;
		}
		/* else: wildcard "*" matches any value - continue */
	}

done:
	/* Handle negation */
	if (pattern->vp_flags & VLABEL_MATCH_NEGATE)
		match = !match;

	return (match);
}

/*
 * vlabel_label_to_string - Convert a label to string representation
 *
 * @vl: Label to convert
 * @buf: Output buffer
 * @buflen: Size of output buffer
 *
 * Returns number of characters written (not including null terminator),
 * or -1 on error.
 */
int
vlabel_label_to_string(const struct vlabel_label *vl, char *buf, size_t buflen)
{
	size_t len;

	if (vl == NULL || buf == NULL || buflen == 0)
		return (-1);

	/* Just use the raw string - it's authoritative */
	len = strlcpy(buf, vl->vl_raw, buflen);
	return (len >= buflen ? -1 : (int)len);
}

/*
 * vlabel_pattern_parse - Parse a pattern string into a pattern structure
 *
 * @str: Pattern string in comma-separated format "key1=val1,key2=val2,..."
 *       or "*" for wildcard, or "!pattern" for negation
 * @len: Length of string
 * @pattern: Pattern structure to populate
 *
 * Note: Patterns use comma-separated format (for rule definitions),
 * while labels use newline-separated format (for extended attributes).
 *
 * Returns 0 on success, error code on failure.
 */
int
vlabel_pattern_parse(const char *str, size_t len, struct vlabel_pattern *pattern)
{
	const char *p, *end, *comma, *eq;
	size_t keylen, valuelen;
	struct vlabel_pair *pair;

	if (str == NULL || pattern == NULL)
		return (EINVAL);

	memset(pattern, 0, sizeof(*pattern));

	/* Check for negation prefix */
	if (len > 0 && str[0] == '!') {
		pattern->vp_flags |= VLABEL_MATCH_NEGATE;
		str++;
		len--;
	}

	/* Empty or "*" means wildcard - match everything */
	if (len == 0 || (len == 1 && str[0] == '*'))
		return (0);

	if (len > VLABEL_MAX_LABEL_LEN) {
		VLABEL_DPRINTF("pattern_parse: pattern too long (%zu > %d)",
		    len, VLABEL_MAX_LABEL_LEN);
		return (EINVAL);
	}

	/* Parse comma-separated key=value pairs */
	p = str;
	end = str + len;

	while (p < end) {
		/* Find next comma or end of string */
		comma = memchr(p, ',', end - p);
		if (comma == NULL)
			comma = end;

		/* Skip empty segments */
		if (comma == p) {
			p = comma + 1;
			continue;
		}

		/* Check pair limit */
		if (pattern->vp_npairs >= VLABEL_MAX_PAIRS) {
			VLABEL_DPRINTF("pattern_parse: too many pairs (max %d)",
			    VLABEL_MAX_PAIRS);
			return (E2BIG);
		}

		/* Find '=' separator */
		eq = memchr(p, '=', comma - p);
		if (eq == NULL) {
			VLABEL_DPRINTF("pattern_parse: missing '=' in pair");
			return (EINVAL);
		}

		keylen = eq - p;
		valuelen = comma - eq - 1;

		if (keylen == 0 || keylen >= VLABEL_MAX_KEY_LEN) {
			VLABEL_DPRINTF("pattern_parse: key length %zu invalid (max %d)",
			    keylen, VLABEL_MAX_KEY_LEN - 1);
			return (EINVAL);
		}
		if (valuelen >= VLABEL_MAX_VALUE_LEN) {
			VLABEL_DPRINTF("pattern_parse: value length %zu too long (max %d)",
			    valuelen, VLABEL_MAX_VALUE_LEN - 1);
			return (EINVAL);
		}

		/* Store this pair */
		pair = &pattern->vp_pairs[pattern->vp_npairs];
		memcpy(pair->vp_key, p, keylen);
		pair->vp_key[keylen] = '\0';
		memcpy(pair->vp_value, eq + 1, valuelen);
		pair->vp_value[valuelen] = '\0';
		pattern->vp_npairs++;

		p = comma + 1;
	}

	return (0);
}
