/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * Simple Line Format Parser
 *
 * Parses vLabel rules in a simple line-based format for CLI use.
 *
 * Format:
 *   action operations subject -> object [context:constraints]
 *
 * Examples:
 *   deny exec * -> type=untrusted
 *   allow read,write domain=web -> domain=web
 *   allow exec type=admin -> * context:jail=host
 *   transition exec type=user -> type=setuid,name=su => type=admin
 *
 * Pattern format:
 *   *                  - match anything
 *   type=value         - match type field
 *   domain=value       - match domain field
 *   name=value         - match name field
 *   level=value        - match level field
 *   type=a,domain=b    - match multiple fields
 *   !type=value        - negate match
 *
 * Context format:
 *   context:jail=host          - must be on host
 *   context:jail=any           - must be in a jail
 *   context:jail=5             - must be in jail 5
 *   context:sandboxed=true     - must be in capability mode
 *   context:uid=0              - must be root
 */

#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vlabeld.h"

/* Static rule ID counter */
static uint32_t next_rule_id = 1000;

/*
 * Skip whitespace
 */
static const char *
skip_ws(const char *s)
{
	while (*s && isspace((unsigned char)*s))
		s++;
	return (s);
}

/*
 * Parse a word (non-whitespace sequence)
 */
static const char *
parse_word(const char *s, char *buf, size_t buflen)
{
	size_t i = 0;

	s = skip_ws(s);
	while (*s && !isspace((unsigned char)*s) && i < buflen - 1) {
		buf[i++] = *s++;
	}
	buf[i] = '\0';

	return (s);
}

/*
 * Parse action: allow, deny, transition
 */
static int
parse_action(const char *word, uint8_t *action)
{
	if (strcasecmp(word, "allow") == 0) {
		*action = VLABEL_ACTION_ALLOW;
		return (0);
	}
	if (strcasecmp(word, "deny") == 0) {
		*action = VLABEL_ACTION_DENY;
		return (0);
	}
	if (strcasecmp(word, "transition") == 0) {
		*action = VLABEL_ACTION_TRANSITION;
		return (0);
	}
	return (-1);
}

/*
 * Parse operations: exec, read, write, exec,read,write, all, *
 */
static int
parse_operations(const char *word, uint32_t *ops)
{
	char buf[256];
	char *p, *tok;

	*ops = 0;
	strlcpy(buf, word, sizeof(buf));

	for (tok = strtok_r(buf, ",", &p); tok != NULL;
	     tok = strtok_r(NULL, ",", &p)) {
		if (strcasecmp(tok, "exec") == 0)
			*ops |= VLABEL_OP_EXEC;
		else if (strcasecmp(tok, "read") == 0)
			*ops |= VLABEL_OP_READ;
		else if (strcasecmp(tok, "write") == 0)
			*ops |= VLABEL_OP_WRITE;
		else if (strcasecmp(tok, "mmap") == 0)
			*ops |= VLABEL_OP_MMAP;
		else if (strcasecmp(tok, "link") == 0)
			*ops |= VLABEL_OP_LINK;
		else if (strcasecmp(tok, "rename") == 0)
			*ops |= VLABEL_OP_RENAME;
		else if (strcasecmp(tok, "unlink") == 0)
			*ops |= VLABEL_OP_UNLINK;
		else if (strcasecmp(tok, "chdir") == 0)
			*ops |= VLABEL_OP_CHDIR;
		else if (strcasecmp(tok, "stat") == 0)
			*ops |= VLABEL_OP_STAT;
		else if (strcasecmp(tok, "readdir") == 0)
			*ops |= VLABEL_OP_READDIR;
		else if (strcasecmp(tok, "create") == 0)
			*ops |= VLABEL_OP_CREATE;
		else if (strcasecmp(tok, "setextattr") == 0)
			*ops |= VLABEL_OP_SETEXTATTR;
		else if (strcasecmp(tok, "getextattr") == 0)
			*ops |= VLABEL_OP_GETEXTATTR;
		else if (strcasecmp(tok, "lookup") == 0)
			*ops |= VLABEL_OP_LOOKUP;
		else if (strcasecmp(tok, "open") == 0)
			*ops |= VLABEL_OP_OPEN;
		else if (strcasecmp(tok, "access") == 0)
			*ops |= VLABEL_OP_ACCESS;
		else if (strcasecmp(tok, "debug") == 0)
			*ops |= VLABEL_OP_DEBUG;
		else if (strcasecmp(tok, "signal") == 0)
			*ops |= VLABEL_OP_SIGNAL;
		else if (strcasecmp(tok, "sched") == 0)
			*ops |= VLABEL_OP_SCHED;
		else if (strcasecmp(tok, "all") == 0 || strcmp(tok, "*") == 0)
			*ops |= VLABEL_OP_ALL;
		else
			return (-1);
	}

	if (*ops == 0)
		*ops = VLABEL_OP_ALL;

	return (0);
}

/*
 * Parse a pattern: key1=val1,key2=val2 or * for wildcard
 *
 * The new vlabel_pattern_io uses a simple string field (vp_pattern)
 * that supports arbitrary key=value pairs. The kernel parses the string.
 *
 * Pattern formats:
 *   *                      - match anything (wildcard)
 *   key1=val1              - must have key1=val1
 *   key1=val1,key2=val2    - must have both
 *   key=*                  - must have key (any value)
 *   !pattern               - negate the match
 */
static int
parse_pattern(const char *word, struct vlabel_pattern_io *pattern)
{
	const char *pattern_start;

	memset(pattern, 0, sizeof(*pattern));

	/* Wildcard */
	if (strcmp(word, "*") == 0) {
		strlcpy(pattern->vp_pattern, "*", sizeof(pattern->vp_pattern));
		return (0);
	}

	/* Check for negation prefix */
	pattern_start = word;
	if (word[0] == '!') {
		pattern->vp_flags |= VLABEL_MATCH_NEGATE;
		pattern_start = word + 1;
	}

	/* Store the pattern string directly - kernel will parse it */
	if (strlen(pattern_start) >= sizeof(pattern->vp_pattern)) {
		fprintf(stderr, "pattern too long: %s\n", word);
		return (-1);
	}

	strlcpy(pattern->vp_pattern, pattern_start, sizeof(pattern->vp_pattern));

	return (0);
}

/*
 * Parse context: context:jail=host,sandboxed=true
 */
static int
parse_context(const char *word, struct vlabel_context_io *ctx)
{
	char buf[256];
	char *p, *tok;
	char *key, *val;

	memset(ctx, 0, sizeof(*ctx));

	/* Must start with "context:" */
	if (strncasecmp(word, "context:", 8) != 0)
		return (-1);

	strlcpy(buf, word + 8, sizeof(buf));

	for (tok = strtok_r(buf, ",", &p); tok != NULL;
	     tok = strtok_r(NULL, ",", &p)) {
		char *endptr;
		long num;

		key = tok;
		val = strchr(tok, '=');
		if (val == NULL)
			continue;
		*val++ = '\0';

		if (strcasecmp(key, "jail") == 0) {
			ctx->vc_flags |= VLABEL_CTX_JAIL;
			if (strcasecmp(val, "host") == 0)
				ctx->vc_jail_check = 0;
			else if (strcasecmp(val, "any") == 0)
				ctx->vc_jail_check = -1;
			else {
				errno = 0;
				num = strtol(val, &endptr, 10);
				if (errno != 0 || *endptr != '\0' || num < 0) {
					fprintf(stderr, "invalid jail ID: %s\n", val);
					return (-1);
				}
				ctx->vc_jail_check = (int)num;
			}
		} else if (strcasecmp(key, "sandboxed") == 0) {
			ctx->vc_flags |= VLABEL_CTX_CAP_SANDBOXED;
			ctx->vc_cap_sandboxed = (strcasecmp(val, "true") == 0 ||
			    strcmp(val, "1") == 0);
		} else if (strcasecmp(key, "tty") == 0) {
			ctx->vc_flags |= VLABEL_CTX_HAS_TTY;
			ctx->vc_has_tty = (strcasecmp(val, "true") == 0 ||
			    strcmp(val, "1") == 0);
		} else if (strcasecmp(key, "uid") == 0) {
			ctx->vc_flags |= VLABEL_CTX_UID;
			errno = 0;
			num = strtol(val, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || num < 0) {
				fprintf(stderr, "invalid uid: %s\n", val);
				return (-1);
			}
			ctx->vc_uid = (uint32_t)num;
		} else if (strcasecmp(key, "gid") == 0) {
			ctx->vc_flags |= VLABEL_CTX_GID;
			errno = 0;
			num = strtol(val, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || num < 0) {
				fprintf(stderr, "invalid gid: %s\n", val);
				return (-1);
			}
			ctx->vc_gid = (uint32_t)num;
		} else if (strcasecmp(key, "ruid") == 0) {
			ctx->vc_flags |= VLABEL_CTX_RUID;
			errno = 0;
			num = strtol(val, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || num < 0) {
				fprintf(stderr, "invalid ruid: %s\n", val);
				return (-1);
			}
			ctx->vc_uid = (uint32_t)num;
		}
	}

	return (0);
}

/*
 * Parse a rule line
 *
 * Format: action operations subject -> object [context:...] [=> newlabel]
 *
 * Returns 0 on success, -1 on parse error.
 */
int
vlabeld_parse_line(const char *line, struct vlabel_rule_io *rule)
{
	char word[256];
	const char *p;

	memset(rule, 0, sizeof(*rule));
	rule->vr_id = next_rule_id++;

	p = skip_ws(line);

	/* Skip empty lines and comments */
	if (*p == '\0' || *p == '#')
		return (1);	/* Not an error, just skip */

	/* Action */
	p = parse_word(p, word, sizeof(word));
	if (parse_action(word, &rule->vr_action) < 0) {
		fprintf(stderr, "invalid action: %s\n", word);
		return (-1);
	}

	/* Operations */
	p = parse_word(p, word, sizeof(word));
	if (parse_operations(word, &rule->vr_operations) < 0) {
		fprintf(stderr, "invalid operations: %s\n", word);
		return (-1);
	}

	/* Subject pattern */
	p = parse_word(p, word, sizeof(word));
	if (parse_pattern(word, &rule->vr_subject) < 0) {
		fprintf(stderr, "invalid subject pattern: %s\n", word);
		return (-1);
	}

	/* Arrow "->" */
	p = parse_word(p, word, sizeof(word));
	if (strcmp(word, "->") != 0) {
		fprintf(stderr, "expected '->', got: %s\n", word);
		return (-1);
	}

	/* Object pattern */
	p = parse_word(p, word, sizeof(word));
	if (parse_pattern(word, &rule->vr_object) < 0) {
		fprintf(stderr, "invalid object pattern: %s\n", word);
		return (-1);
	}

	/* Optional: context or transition arrow */
	p = skip_ws(p);
	while (*p != '\0') {
		p = parse_word(p, word, sizeof(word));
		if (word[0] == '\0')
			break;

		if (strncasecmp(word, "context:", 8) == 0) {
			if (parse_context(word, &rule->vr_context) < 0) {
				fprintf(stderr, "invalid context: %s\n", word);
				return (-1);
			}
		} else if (strcmp(word, "=>") == 0) {
			/* Transition label */
			p = parse_word(p, word, sizeof(word));
			strlcpy(rule->vr_newlabel, word, sizeof(rule->vr_newlabel));
		}

		p = skip_ws(p);
	}

	return (0);
}
