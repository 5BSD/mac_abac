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

	if (vlabel_zone == NULL)
		panic("vlabel: unable to create label zone");

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
 * NOTE: We intentionally do NOT destroy the UMA zone here because
 * there may still be vnodes with our labels attached. The MAC framework
 * calls vnode_destroy_label AFTER mpo_destroy, so our zone must remain
 * valid. The zone memory will persist until reboot, but this is
 * acceptable for a security module that's typically loaded at boot.
 */
void
vlabel_label_destroy(void)
{

	/*
	 * Don't destroy the zone - labels may still be in use.
	 * Just log statistics for debugging.
	 */
	VLABEL_DPRINTF("label subsystem destroyed (alloc=%ju, freed=%ju)",
	    (uintmax_t)vlabel_labels_allocated,
	    (uintmax_t)vlabel_labels_freed);
}

/*
 * vlabel_label_alloc - Allocate a new label structure
 *
 * @flags: M_WAITOK or M_NOWAIT
 *
 * Returns a zeroed label structure, or NULL if allocation fails
 * (only possible with M_NOWAIT).
 */
struct vlabel_label *
vlabel_label_alloc(int flags)
{
	struct vlabel_label *vl;

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
 * parse_kv_pair - Parse a single key=value pair
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
	char key[VLABEL_MAX_KEY_LEN];
	char value[VLABEL_MAX_VALUE_LEN];
	const char *eq;
	size_t keylen, valuelen;

	/* Find the '=' separator */
	eq = memchr(str, '=', len);
	if (eq == NULL)
		return (EINVAL);

	keylen = eq - str;
	valuelen = len - keylen - 1;

	/* Validate lengths */
	if (keylen == 0 || keylen >= VLABEL_MAX_KEY_LEN)
		return (EINVAL);
	if (valuelen >= VLABEL_MAX_VALUE_LEN)
		return (EINVAL);

	/* Copy key and value */
	memcpy(key, str, keylen);
	key[keylen] = '\0';

	memcpy(value, eq + 1, valuelen);
	value[valuelen] = '\0';

	/* Store in appropriate field */
	if (strcmp(key, "type") == 0) {
		strlcpy(vl->vl_type, value, sizeof(vl->vl_type));
		vl->vl_flags |= VLABEL_MATCH_TYPE;
	} else if (strcmp(key, "domain") == 0) {
		strlcpy(vl->vl_domain, value, sizeof(vl->vl_domain));
		vl->vl_flags |= VLABEL_MATCH_DOMAIN;
	} else if (strcmp(key, "name") == 0) {
		strlcpy(vl->vl_name, value, sizeof(vl->vl_name));
		vl->vl_flags |= VLABEL_MATCH_NAME;
	} else if (strcmp(key, "level") == 0) {
		strlcpy(vl->vl_level, value, sizeof(vl->vl_level));
		vl->vl_flags |= VLABEL_MATCH_LEVEL;
	}
	/* Unknown keys are silently ignored for forward compatibility */

	return (0);
}

/*
 * vlabel_label_parse - Parse a label string into a label structure
 *
 * @str: Label string in format "key1=val1,key2=val2,..."
 * @len: Length of string (not including null terminator)
 * @vl: Label structure to populate (must be zeroed)
 *
 * Returns 0 on success, error code on failure.
 *
 * Example input: "type=system,domain=daemon,name=sshd,level=high"
 */
int
vlabel_label_parse(const char *str, size_t len, struct vlabel_label *vl)
{
	const char *p, *end, *comma;
	int error;

	/* Validate inputs */
	if (str == NULL || vl == NULL)
		return (EINVAL);

	if (len == 0 || len > VLABEL_MAX_LABEL_LEN) {
		atomic_add_64(&vlabel_parse_errors, 1);
		return (EINVAL);
	}

	/* Store raw label string */
	strlcpy(vl->vl_raw, str, sizeof(vl->vl_raw));
	vl->vl_hash = vlabel_label_hash(str, len);
	vl->vl_flags = 0;

	/* Parse comma-separated key=value pairs */
	p = str;
	end = str + len;

	while (p < end) {
		/* Find next comma or end of string */
		comma = memchr(p, ',', end - p);
		if (comma == NULL)
			comma = end;

		/* Parse this pair */
		if (comma > p) {
			error = parse_kv_pair(p, comma - p, vl);
			if (error != 0) {
				atomic_add_64(&vlabel_parse_errors, 1);
				return (error);
			}
		}

		/* Move past comma */
		p = comma + 1;
	}

	VLABEL_DPRINTF("parsed label: type=%s domain=%s name=%s level=%s",
	    vl->vl_type[0] ? vl->vl_type : "(none)",
	    vl->vl_domain[0] ? vl->vl_domain : "(none)",
	    vl->vl_name[0] ? vl->vl_name : "(none)",
	    vl->vl_level[0] ? vl->vl_level : "(none)");

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
		strlcpy(vl->vl_raw, "type=user,level=default",
		    sizeof(vl->vl_raw));
		strlcpy(vl->vl_type, "user", sizeof(vl->vl_type));
		strlcpy(vl->vl_level, "default", sizeof(vl->vl_level));
	} else {
		strlcpy(vl->vl_raw, "type=unlabeled,level=default",
		    sizeof(vl->vl_raw));
		strlcpy(vl->vl_type, "unlabeled", sizeof(vl->vl_type));
		strlcpy(vl->vl_level, "default", sizeof(vl->vl_level));
	}

	vl->vl_hash = vlabel_label_hash(vl->vl_raw, strlen(vl->vl_raw));
	vl->vl_flags = VLABEL_MATCH_TYPE | VLABEL_MATCH_LEVEL;
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
 * - Empty pattern field = wildcard (matches anything)
 * - Non-empty field must match exactly
 * - VLABEL_MATCH_NEGATE inverts the result
 */
bool
vlabel_label_match(const struct vlabel_label *label,
    const struct vlabel_pattern *pattern)
{
	bool match = true;

	if (label == NULL || pattern == NULL)
		return (false);

	/* Check each field that's specified in the pattern */
	if ((pattern->vp_flags & VLABEL_MATCH_TYPE) &&
	    pattern->vp_type[0] != '\0') {
		if (strcmp(label->vl_type, pattern->vp_type) != 0)
			match = false;
	}

	if (match && (pattern->vp_flags & VLABEL_MATCH_DOMAIN) &&
	    pattern->vp_domain[0] != '\0') {
		if (strcmp(label->vl_domain, pattern->vp_domain) != 0)
			match = false;
	}

	if (match && (pattern->vp_flags & VLABEL_MATCH_NAME) &&
	    pattern->vp_name[0] != '\0') {
		if (strcmp(label->vl_name, pattern->vp_name) != 0)
			match = false;
	}

	if (match && (pattern->vp_flags & VLABEL_MATCH_LEVEL) &&
	    pattern->vp_level[0] != '\0') {
		if (strcmp(label->vl_level, pattern->vp_level) != 0)
			match = false;
	}

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
	int len;

	if (vl == NULL || buf == NULL || buflen == 0)
		return (-1);

	/* If we have a raw string, just use that */
	if (vl->vl_raw[0] != '\0') {
		len = strlcpy(buf, vl->vl_raw, buflen);
		return (len >= buflen ? -1 : len);
	}

	/* Otherwise, build from components */
	len = 0;
	buf[0] = '\0';

	if (vl->vl_type[0] != '\0') {
		len += snprintf(buf + len, buflen - len, "%stype=%s",
		    len > 0 ? "," : "", vl->vl_type);
	}
	if (vl->vl_domain[0] != '\0') {
		len += snprintf(buf + len, buflen - len, "%sdomain=%s",
		    len > 0 ? "," : "", vl->vl_domain);
	}
	if (vl->vl_name[0] != '\0') {
		len += snprintf(buf + len, buflen - len, "%sname=%s",
		    len > 0 ? "," : "", vl->vl_name);
	}
	if (vl->vl_level[0] != '\0') {
		len += snprintf(buf + len, buflen - len, "%slevel=%s",
		    len > 0 ? "," : "", vl->vl_level);
	}

	return (len >= buflen ? -1 : len);
}
