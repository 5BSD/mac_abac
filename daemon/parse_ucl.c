/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * UCL Policy Parser
 *
 * Parses vLabel policy files in UCL format. Also supports JSON since
 * UCL is a superset of JSON.
 *
 * Policy file format:
 *
 * # Set enforcement mode: disabled, permissive, enforcing
 * mode = "enforcing";
 *
 * # Rules are evaluated in order (first match wins)
 * rules = [
 *     {
 *         id = 1;
 *         action = "deny";
 *         operations = ["exec"];
 *         object = { type = "untrusted"; };
 *     },
 *     {
 *         id = 2;
 *         action = "allow";
 *         operations = ["read", "write"];
 *         subject = { domain = "web"; };
 *         object = { domain = "web"; };
 *     },
 *     {
 *         id = 3;
 *         action = "allow";
 *         operations = ["exec"];
 *         subject = { type = "admin"; };
 *         context = { jail = "host"; };
 *     },
 *     {
 *         id = 100;
 *         action = "transition";
 *         operations = ["exec"];
 *         subject = { type = "user"; };
 *         object = { type = "setuid"; name = "su"; };
 *         newlabel = "type=admin,domain=system";
 *     }
 * ];
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <ucl.h>

#include "vlabeld.h"

/* Operation name to bitmask mapping */
static const struct {
	const char	*name;
	uint32_t	 op;
} op_map[] = {
	{ "exec",	VLABEL_OP_EXEC },
	{ "read",	VLABEL_OP_READ },
	{ "write",	VLABEL_OP_WRITE },
	{ "mmap",	VLABEL_OP_MMAP },
	{ "link",	VLABEL_OP_LINK },
	{ "rename",	VLABEL_OP_RENAME },
	{ "unlink",	VLABEL_OP_UNLINK },
	{ "chdir",	VLABEL_OP_CHDIR },
	{ "stat",	VLABEL_OP_STAT },
	{ "readdir",	VLABEL_OP_READDIR },
	{ "create",	VLABEL_OP_CREATE },
	{ "setextattr",	VLABEL_OP_SETEXTATTR },
	{ "getextattr",	VLABEL_OP_GETEXTATTR },
	{ "lookup",	VLABEL_OP_LOOKUP },
	{ "open",	VLABEL_OP_OPEN },
	{ "access",	VLABEL_OP_ACCESS },
	{ "all",	VLABEL_OP_ALL },
	{ "*",		VLABEL_OP_ALL },
	{ NULL,		0 }
};

/* Action name to value mapping */
static const struct {
	const char	*name;
	uint8_t		 action;
} action_map[] = {
	{ "allow",	VLABEL_ACTION_ALLOW },
	{ "deny",	VLABEL_ACTION_DENY },
	{ "transition",	VLABEL_ACTION_TRANSITION },
	{ NULL,		0 }
};

static bool verbose_mode = false;

static void
log_verbose(const char *fmt, ...)
{
	va_list ap;

	if (!verbose_mode)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

/*
 * Parse operation list (array of strings or single string)
 */
static uint32_t
parse_operations(const ucl_object_t *obj)
{
	const ucl_object_t *elem;
	ucl_object_iter_t it = NULL;
	uint32_t ops = 0;
	const char *str;
	int i;

	if (obj == NULL)
		return (VLABEL_OP_ALL);

	if (ucl_object_type(obj) == UCL_STRING) {
		str = ucl_object_tostring(obj);
		for (i = 0; op_map[i].name != NULL; i++) {
			if (strcasecmp(str, op_map[i].name) == 0) {
				ops |= op_map[i].op;
				break;
			}
		}
	} else if (ucl_object_type(obj) == UCL_ARRAY) {
		while ((elem = ucl_object_iterate(obj, &it, true)) != NULL) {
			if (ucl_object_type(elem) != UCL_STRING)
				continue;
			str = ucl_object_tostring(elem);
			for (i = 0; op_map[i].name != NULL; i++) {
				if (strcasecmp(str, op_map[i].name) == 0) {
					ops |= op_map[i].op;
					break;
				}
			}
		}
	}

	return (ops);
}

/*
 * Parse action string
 */
static int
parse_action(const ucl_object_t *obj, uint8_t *action)
{
	const char *str;
	int i;

	if (obj == NULL || ucl_object_type(obj) != UCL_STRING)
		return (-1);

	str = ucl_object_tostring(obj);
	for (i = 0; action_map[i].name != NULL; i++) {
		if (strcasecmp(str, action_map[i].name) == 0) {
			*action = action_map[i].action;
			return (0);
		}
	}

	return (-1);
}

/*
 * Parse a pattern (subject or object)
 *
 * The new vlabel_pattern_io uses a simple string field (vp_pattern)
 * that supports arbitrary key=value pairs. We build the string from
 * UCL object keys.
 *
 * UCL format (supports arbitrary keys):
 *   subject = { type = "app"; domain = "web"; sensitivity = "secret"; }
 *   object = { compartment = "hr"; level = "high"; }
 *   subject = "*";  -- wildcard
 *   object = "type=app,domain=web";  -- string form
 *
 * The pattern string format is: "key1=val1,key2=val2,..."
 */
static void
parse_pattern(const ucl_object_t *obj, struct vlabel_pattern_io *pattern)
{
	const ucl_object_t *val;
	ucl_object_iter_t it = NULL;
	const char *key, *str;
	size_t pos;
	bool first;
	bool negate = false;

	memset(pattern, 0, sizeof(*pattern));

	if (obj == NULL)
		return;

	/* Handle string form: "*" or "type=app,domain=web" */
	if (ucl_object_type(obj) == UCL_STRING) {
		str = ucl_object_tostring(obj);
		if (str[0] == '!') {
			pattern->vp_flags |= VLABEL_MATCH_NEGATE;
			str++;
		}
		strlcpy(pattern->vp_pattern, str, sizeof(pattern->vp_pattern));
		return;
	}

	if (ucl_object_type(obj) != UCL_OBJECT)
		return;

	/* Check for negate flag in object */
	val = ucl_object_lookup(obj, "negate");
	if (val != NULL && ucl_object_type(val) == UCL_BOOLEAN) {
		negate = ucl_object_toboolean(val);
	}

	/* Build pattern string from all key=value pairs in the object */
	pos = 0;
	first = true;

	while ((val = ucl_object_iterate(obj, &it, true)) != NULL) {
		size_t copied;

		key = ucl_object_key(val);

		/* Skip special keys */
		if (strcmp(key, "negate") == 0)
			continue;

		if (ucl_object_type(val) != UCL_STRING)
			continue;

		str = ucl_object_tostring(val);

		/* Skip wildcard values */
		if (strcmp(str, "*") == 0)
			continue;

		/* Append "key=value" to pattern */
		if (!first && pos < sizeof(pattern->vp_pattern) - 1) {
			pattern->vp_pattern[pos++] = ',';
		}
		first = false;

		/*
		 * strlcpy returns total length it tried to copy, not actual.
		 * Clamp position to avoid buffer overflow on truncation.
		 */
		copied = strlcpy(pattern->vp_pattern + pos, key,
		    sizeof(pattern->vp_pattern) - pos);
		pos = (pos + copied >= sizeof(pattern->vp_pattern)) ?
		    sizeof(pattern->vp_pattern) - 1 : pos + copied;
		if (pos < sizeof(pattern->vp_pattern) - 1) {
			pattern->vp_pattern[pos++] = '=';
		}
		copied = strlcpy(pattern->vp_pattern + pos, str,
		    sizeof(pattern->vp_pattern) - pos);
		pos = (pos + copied >= sizeof(pattern->vp_pattern)) ?
		    sizeof(pattern->vp_pattern) - 1 : pos + copied;
	}

	/* If pattern is empty, treat as wildcard */
	if (pattern->vp_pattern[0] == '\0') {
		strlcpy(pattern->vp_pattern, "*", sizeof(pattern->vp_pattern));
	}

	if (negate)
		pattern->vp_flags |= VLABEL_MATCH_NEGATE;
}

/*
 * Parse context constraints
 */
static void
parse_context(const ucl_object_t *obj, struct vlabel_context_io *ctx)
{
	const ucl_object_t *val;
	const char *str;

	memset(ctx, 0, sizeof(*ctx));

	if (obj == NULL || ucl_object_type(obj) != UCL_OBJECT)
		return;

	/* jail: "host", "any", or jail ID */
	val = ucl_object_lookup(obj, "jail");
	if (val != NULL) {
		ctx->vc_flags |= VLABEL_CTX_JAIL;
		if (ucl_object_type(val) == UCL_STRING) {
			str = ucl_object_tostring(val);
			if (strcasecmp(str, "host") == 0)
				ctx->vc_jail_check = 0;
			else if (strcasecmp(str, "any") == 0)
				ctx->vc_jail_check = -1;
			else {
				char *endptr;
				long jid;
				errno = 0;
				jid = strtol(str, &endptr, 10);
				if (errno != 0 || *endptr != '\0' || jid < 0) {
					vlabeld_log(LOG_WARNING,
					    "invalid jail ID: %s", str);
					ctx->vc_jail_check = 0;
				} else {
					ctx->vc_jail_check = (int)jid;
				}
			}
		} else if (ucl_object_type(val) == UCL_INT) {
			ctx->vc_jail_check = ucl_object_toint(val);
		}
	}

	/* sandboxed: true/false */
	val = ucl_object_lookup(obj, "sandboxed");
	if (val != NULL && ucl_object_type(val) == UCL_BOOLEAN) {
		ctx->vc_flags |= VLABEL_CTX_CAP_SANDBOXED;
		ctx->vc_cap_sandboxed = ucl_object_toboolean(val);
	}

	/* tty: true/false */
	val = ucl_object_lookup(obj, "tty");
	if (val != NULL && ucl_object_type(val) == UCL_BOOLEAN) {
		ctx->vc_flags |= VLABEL_CTX_HAS_TTY;
		ctx->vc_has_tty = ucl_object_toboolean(val);
	}

	/* uid */
	val = ucl_object_lookup(obj, "uid");
	if (val != NULL && ucl_object_type(val) == UCL_INT) {
		ctx->vc_flags |= VLABEL_CTX_UID;
		ctx->vc_uid = ucl_object_toint(val);
	}

	/* gid */
	val = ucl_object_lookup(obj, "gid");
	if (val != NULL && ucl_object_type(val) == UCL_INT) {
		ctx->vc_flags |= VLABEL_CTX_GID;
		ctx->vc_gid = ucl_object_toint(val);
	}

	/* ruid (real uid) */
	val = ucl_object_lookup(obj, "ruid");
	if (val != NULL && ucl_object_type(val) == UCL_INT) {
		ctx->vc_flags |= VLABEL_CTX_RUID;
		ctx->vc_uid = ucl_object_toint(val);
	}
}

/*
 * Parse a single rule object
 */
static int
parse_rule(const ucl_object_t *obj, struct vlabel_rule_io *rule)
{
	const ucl_object_t *val;

	memset(rule, 0, sizeof(*rule));

	if (obj == NULL || ucl_object_type(obj) != UCL_OBJECT)
		return (-1);

	/* id (required) */
	val = ucl_object_lookup(obj, "id");
	if (val == NULL || ucl_object_type(val) != UCL_INT) {
		vlabeld_log(LOG_ERR, "rule missing 'id' field");
		return (-1);
	}
	rule->vr_id = ucl_object_toint(val);

	/* action (required) */
	val = ucl_object_lookup(obj, "action");
	if (parse_action(val, &rule->vr_action) < 0) {
		vlabeld_log(LOG_ERR, "rule %u: invalid or missing 'action'",
		    rule->vr_id);
		return (-1);
	}

	/* operations */
	val = ucl_object_lookup(obj, "operations");
	rule->vr_operations = parse_operations(val);
	if (rule->vr_operations == 0)
		rule->vr_operations = VLABEL_OP_ALL;

	/* subject pattern */
	val = ucl_object_lookup(obj, "subject");
	parse_pattern(val, &rule->vr_subject);

	/* object pattern */
	val = ucl_object_lookup(obj, "object");
	parse_pattern(val, &rule->vr_object);

	/* subject context constraints */
	val = ucl_object_lookup(obj, "context");
	parse_context(val, &rule->vr_subj_context);

	/* object context constraints */
	val = ucl_object_lookup(obj, "obj_context");
	parse_context(val, &rule->vr_obj_context);

	/* newlabel (for transition rules) */
	if (rule->vr_action == VLABEL_ACTION_TRANSITION) {
		val = ucl_object_lookup(obj, "newlabel");
		if (val != NULL && ucl_object_type(val) == UCL_STRING) {
			strlcpy(rule->vr_newlabel, ucl_object_tostring(val),
			    sizeof(rule->vr_newlabel));
		}
	}

	log_verbose("  rule %u: action=%d ops=0x%x subj_flags=0x%x obj_flags=0x%x",
	    rule->vr_id, rule->vr_action, rule->vr_operations,
	    rule->vr_subject.vp_flags, rule->vr_object.vp_flags);

	return (0);
}

/*
 * Parse the rules array
 */
static int
parse_rules(const ucl_object_t *obj)
{
	const ucl_object_t *rule_obj;
	ucl_object_iter_t it = NULL;
	struct vlabel_rule_io rule;
	int count = 0;
	int errors = 0;

	if (obj == NULL || ucl_object_type(obj) != UCL_ARRAY) {
		vlabeld_log(LOG_WARNING, "no 'rules' array found in policy");
		return (0);
	}

	while ((rule_obj = ucl_object_iterate(obj, &it, true)) != NULL) {
		if (parse_rule(rule_obj, &rule) < 0) {
			errors++;
			continue;
		}

		if (vlabeld_add_rule(&rule) < 0) {
			errors++;
			continue;
		}

		count++;
	}

	vlabeld_log(LOG_INFO, "loaded %d rules (%d errors)", count, errors);

	return (errors > 0 ? -1 : 0);
}

/*
 * Parse mode setting
 */
static int
parse_mode(const ucl_object_t *obj)
{
	const char *str;
	int mode;

	if (obj == NULL || ucl_object_type(obj) != UCL_STRING)
		return (0);

	str = ucl_object_tostring(obj);
	if (strcasecmp(str, "disabled") == 0)
		mode = VLABEL_MODE_DISABLED;
	else if (strcasecmp(str, "permissive") == 0)
		mode = VLABEL_MODE_PERMISSIVE;
	else if (strcasecmp(str, "enforcing") == 0)
		mode = VLABEL_MODE_ENFORCING;
	else {
		vlabeld_log(LOG_ERR, "invalid mode: %s", str);
		return (-1);
	}

	log_verbose("setting mode to %s (%d)", str, mode);

	return vlabeld_set_mode(mode);
}

/*
 * Main UCL parsing function
 */
int
vlabeld_parse_ucl(const char *path, bool verbose)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *obj;
	const char *errmsg;
	int error = 0;

	verbose_mode = verbose;

	log_verbose("parsing UCL file: %s", path);

	parser = ucl_parser_new(UCL_PARSER_KEY_LOWERCASE);
	if (parser == NULL) {
		vlabeld_log(LOG_ERR, "ucl_parser_new failed");
		return (-1);
	}

	/* Enable include support */
	ucl_parser_set_filevars(parser, path, true);

	if (!ucl_parser_add_file(parser, path)) {
		errmsg = ucl_parser_get_error(parser);
		vlabeld_log(LOG_ERR, "parse error: %s", errmsg ? errmsg : "unknown");
		ucl_parser_free(parser);
		return (-1);
	}

	root = ucl_parser_get_object(parser);
	ucl_parser_free(parser);

	if (root == NULL) {
		vlabeld_log(LOG_ERR, "failed to get UCL object");
		return (-1);
	}

	/* Parse mode */
	obj = ucl_object_lookup(root, "mode");
	if (parse_mode(obj) < 0)
		error = -1;

	/* Note: audit is now handled by FreeBSD's standard audit subsystem */

	/* Parse rules */
	obj = ucl_object_lookup(root, "rules");
	if (parse_rules(obj) < 0)
		error = -1;

	ucl_object_unref(root);

	return (error);
}

/*
 * Parse rules with callback - for vlabelctl to build packed buffers
 */
static int
parse_rules_with_callback(const ucl_object_t *obj,
    vlabel_rule_callback_t callback, void *ctx)
{
	const ucl_object_t *rule_obj;
	ucl_object_iter_t it = NULL;
	struct vlabel_rule_io rule;
	int count = 0;
	int errors = 0;

	if (obj == NULL || ucl_object_type(obj) != UCL_ARRAY) {
		vlabeld_log(LOG_WARNING, "no 'rules' array found in policy");
		return (0);
	}

	while ((rule_obj = ucl_object_iterate(obj, &it, true)) != NULL) {
		if (parse_rule(rule_obj, &rule) < 0) {
			errors++;
			continue;
		}

		if (callback(&rule, ctx) < 0) {
			errors++;
			continue;
		}

		count++;
	}

	vlabeld_log(LOG_INFO, "parsed %d rules (%d errors)", count, errors);

	return (errors > 0 ? -1 : 0);
}

/*
 * Parse UCL file with callback for each rule
 * This is used by vlabelctl which needs to build packed rule buffers
 * rather than sending rules directly to kernel.
 */
int
vlabeld_parse_ucl_with_callback(const char *path, bool verbose,
    vlabel_rule_callback_t callback, void *ctx)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *obj;
	const char *errmsg;
	int error = 0;

	verbose_mode = verbose;

	log_verbose("parsing UCL file: %s", path);

	parser = ucl_parser_new(UCL_PARSER_KEY_LOWERCASE);
	if (parser == NULL) {
		vlabeld_log(LOG_ERR, "ucl_parser_new failed");
		return (-1);
	}

	/* Enable include support */
	ucl_parser_set_filevars(parser, path, true);

	if (!ucl_parser_add_file(parser, path)) {
		errmsg = ucl_parser_get_error(parser);
		vlabeld_log(LOG_ERR, "parse error: %s", errmsg ? errmsg : "unknown");
		ucl_parser_free(parser);
		return (-1);
	}

	root = ucl_parser_get_object(parser);
	ucl_parser_free(parser);

	if (root == NULL) {
		vlabeld_log(LOG_ERR, "failed to get UCL object");
		return (-1);
	}

	/* Parse rules only - mode is not handled by vlabelctl load */
	obj = ucl_object_lookup(root, "rules");
	if (parse_rules_with_callback(obj, callback, ctx) < 0)
		error = -1;

	ucl_object_unref(root);

	return (error);
}
